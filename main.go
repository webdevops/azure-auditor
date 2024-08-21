package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"time"

	sprig "github.com/Masterminds/sprig/v3"
	"github.com/dustin/go-humanize"
	"github.com/google/uuid"
	flags "github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/webdevops/go-common/azuresdk/prometheus/tracing"
	yaml "gopkg.in/yaml.v3"

	auditor "github.com/webdevops/azure-auditor/auditor"
	"github.com/webdevops/azure-auditor/auditor/types"
	"github.com/webdevops/azure-auditor/auditor/validator"
	"github.com/webdevops/azure-auditor/config"
)

const (
	Author = "webdevops.io"

	UserAgent = "azure-auditor/"
)

var (
	argparser *flags.Parser
	Opts      config.Opts

	azureAuditor *auditor.AzureAuditor

	// Git version information
	gitCommit = "<unknown>"
	gitTag    = "<unknown>"
)

func main() {
	initArgparser()
	defer initLogger().Sync() // nolint:errcheck

	logger.Infof("starting azure-auditor v%s (%s; %s; by %v)", gitTag, gitCommit, runtime.Version(), Author)
	logger.Info(string(Opts.GetJson()))

	initSystem()

	logger.Infof("starting audit")
	azureAuditor = auditor.NewAzureAuditor()
	azureAuditor.Opts = Opts
	azureAuditor.Logger = logger
	azureAuditor.UserAgent = UserAgent + gitTag
	azureAuditor.SetConfigs(Opts.Config...)
	azureAuditor.Run()

	logger.Infof("Starting http server on %s", Opts.Server.Bind)
	startHttpServer()
}

func initArgparser() {
	argparser = flags.NewParser(&Opts, flags.Default)
	_, err := argparser.Parse()

	// check if there is a parse error
	if err != nil {
		var flagsErr *flags.Error
		if ok := errors.As(err, &flagsErr); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			fmt.Println()
			argparser.WriteHelp(os.Stdout)
			os.Exit(1)
		}
	}
}

// start and handle prometheus handler
func startHttpServer() {
	var err error
	mux := http.NewServeMux()

	if Opts.Server.PathReport == "/" {
		Opts.Server.PathReport = ""
	}

	endpoints := map[string]string{
		"healthz":  "/healthz",
		"readyz":   "/readyz",
		"metrics":  "/metrics",
		"frontend": Opts.Server.PathReport + "/",
		"data":     Opts.Server.PathReport + "/data",
		"config":   Opts.Server.PathReport + "/config",
	}

	// healthz
	mux.HandleFunc(endpoints["healthz"], func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprint(w, "Ok"); err != nil {
			logger.Error(err)
		}
	})

	// readyz
	mux.HandleFunc(endpoints["readyz"], func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprint(w, "Ok"); err != nil {
			logger.Error(err)
		}
	})

	// report
	tmpl := template.New("report")

	cssOptimizeRegexp := regexp.MustCompile(`\n[\s]*`)
	tmpl, err = tmpl.Funcs(template.FuncMap{
		"toYaml": func(obj interface{}) string {
			out, _ := yaml.Marshal(obj)
			return string(out)
		},
		"raw": func(val string) template.HTML {
			return template.HTML(val) // #nosec G203 this template function is for returning unescaped html
		},
		"rawHtml": func(val string) template.HTML {
			return template.HTML(val) // #nosec G203 this template function is for returning unescaped html
		},
		"rawCss": func(val string) template.CSS {
			val = cssOptimizeRegexp.ReplaceAllString(val, " ")
			return template.CSS(val) // #nosec G203 this template function is for returning unescaped html
		},
		"rawJs": func(val string) template.JS {
			jsFilter := regexp.MustCompile(`(?m)^[\s]*(//.+$)?`)
			if !Opts.Logger.Development {
				val = jsFilter.ReplaceAllString(val, "")
				val = jsFilter.ReplaceAllString(val, "")
				val = strings.ReplaceAll(val, "{\n", "{")
				val = strings.ReplaceAll(val, "}\n", "};")
				val = strings.ReplaceAll(val, ";\n", ";")
				val = strings.ReplaceAll(val, ",\n", ",")
			}
			return template.JS(val) // #nosec G203 this template function is for returning unescaped html
		},
		"reportTitle": func(val string) (reportTitle string) {
			reportTitle = val
			if pos := strings.Index(reportTitle, ":"); pos >= 0 {
				reportTitle = strings.TrimPrefix(reportTitle, reportTitle[0:pos+1])
			}
			return
		},
		"humanizeReportCount": func(val int64) string {
			return humanize.SIWithDigits(float64(val), 1, "")
		},
		"include": func(name string, data interface{}) string {
			var buf strings.Builder
			err := tmpl.ExecuteTemplate(&buf, name, data)
			if err != nil {
				logger.Panic(err.Error())
			}
			return buf.String()
		},
		"version": func() string {
			return gitTag
		},
	}).Funcs(sprig.HtmlFuncMap()).ParseGlob("./templates/*")
	if err != nil {
		logger.Panic(err)
	}

	mux.HandleFunc(endpoints["frontend"], func(w http.ResponseWriter, r *http.Request) {
		cspNonce := base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))

		w.Header().Add("Content-Type", "text/html")
		w.Header().Add("Referrer-Policy", "same-origin")
		w.Header().Add("X-Frame-Options", "DENY")
		w.Header().Add("X-XSS-Protection", "1; mode=block")
		w.Header().Add("X-Content-Type-Options", "nosniff")
		w.Header().Add("Content-Security-Policy",
			fmt.Sprintf(
				"default-src 'self'; script-src 'nonce-%[1]s'; style-src 'nonce-%[1]s' 'unsafe-inline'; img-src 'self' data:",
				cspNonce,
			),
		)
		selectedReport := r.URL.Query().Get("report")

		templatePayload := struct {
			Nonce                string
			AzureAuditor         auditor.AzureAuditor
			Config               auditor.AuditConfig
			ReportTitle          string
			ReportConfig         *validator.AuditConfigValidation
			Reports              map[string]*auditor.AzureAuditorReport
			ServerPathReport     string
			RequestReport        string
			ReportPaginationSize int
		}{
			Nonce:                cspNonce,
			Config:               azureAuditor.GetConfig(),
			ReportTitle:          Opts.Report.Title,
			ReportConfig:         nil,
			Reports:              azureAuditor.GetReport(),
			ServerPathReport:     Opts.Server.PathReport,
			RequestReport:        "",
			ReportPaginationSize: Opts.Report.PaginationSize,
		}

		reportInfo := strings.SplitN(selectedReport, ":", 2)
		switch reportInfo[0] {
		case "RoleAssignment":
			templatePayload.ReportConfig = templatePayload.Config.RoleAssignments
			templatePayload.RequestReport = selectedReport
		case "ResourceGroup":
			templatePayload.ReportConfig = templatePayload.Config.ResourceGroups
			templatePayload.RequestReport = selectedReport
		case "ResourceProvider":
			templatePayload.ReportConfig = templatePayload.Config.ResourceProviders
			templatePayload.RequestReport = selectedReport
		case "ResourceProviderFeature":
			templatePayload.ReportConfig = templatePayload.Config.ResourceProviderFeatures
			templatePayload.RequestReport = selectedReport
		case "KeyvaultAccessPolicy":
			templatePayload.ReportConfig = templatePayload.Config.KeyvaultAccessPolicies
			templatePayload.RequestReport = selectedReport
		case "ResourceGraph":
			if len(reportInfo) == 2 && reportInfo[1] != "" {
				if v, ok := templatePayload.Config.ResourceGraph.Queries[reportInfo[1]]; ok {
					templatePayload.ReportConfig = v
					templatePayload.RequestReport = selectedReport
				}
			}
		case "LogAnalytics":
			if len(reportInfo) == 2 && reportInfo[1] != "" {
				if v, ok := templatePayload.Config.LogAnalytics.Queries[reportInfo[1]]; ok {
					templatePayload.ReportConfig = v
					templatePayload.RequestReport = selectedReport
				}
			}
		}

		if err := tmpl.ExecuteTemplate(w, "report.html", templatePayload); err != nil {
			logger.Error(err)
		}
	})

	mux.HandleFunc(endpoints["data"], func(w http.ResponseWriter, r *http.Request) {
		var reportGroupBy *string
		var reportFields *[]string
		var reportStatus *types.RuleStatus

		if val := r.URL.Query().Get("groupBy"); val != "" {
			reportGroupBy = &val
		}

		if val := r.URL.Query().Get("fields"); val != "" && val != "*" {
			fieldList := []string{}
			for _, field := range strings.Split(val, ":") {
				fieldList = append(fieldList, strings.TrimSpace(field))
			}
			reportFields = &fieldList
		}

		if val := r.URL.Query().Get("status"); val != "" {
			valStatus := types.StringToRuleStatus(val)
			reportStatus = &valStatus
		}

		if reportName := r.URL.Query().Get("report"); reportName != "" {
			reportList := azureAuditor.GetReport()
			if report, ok := reportList[reportName]; ok {

				if report.UpdateTime != nil {
					w.Header().Add("x-report-time", report.UpdateTime.Format(time.RFC1123Z))
				} else {
					w.Header().Add("x-report-time", "init")
				}

				reportData := []auditor.AzureAuditorReportLine{}
				for _, row := range report.Lines {
					line := auditor.AzureAuditorReportLine{} // nolint:ineffassign
					line = *row

					// filter: status
					if reportStatus != nil {
						if row.Status != (*reportStatus).String() {
							continue
						}
					}

					// group by
					line.GroupBy = ""
					if reportGroupBy != nil {
						switch *reportGroupBy {
						case "rule", "ruleid":
							line.GroupBy = line.RuleID
						case "status":
							line.GroupBy = line.Status
						default:
							if val, ok := line.Resource[*reportGroupBy]; ok {
								line.GroupBy = val
							}
						}
					}

					// report field filtering
					if reportFields != nil {
						resource := map[string]interface{}{}
						for _, fieldName := range *reportFields {
							if val, ok := line.Resource[fieldName]; ok {
								resource[fieldName] = val
							}
						}
						line.Resource = resource
					}

					reportData = append(reportData, line)
				}

				// unique filter
				reportDataUnique := map[[20]byte]auditor.AzureAuditorReportLine{}
				for _, line := range reportData {
					hash := line.Hash()

					if existingLine, exists := reportDataUnique[hash]; exists {
						existingLine.Count++
						reportDataUnique[hash] = existingLine
					} else {
						line.Count = 1
						reportDataUnique[hash] = line
					}
				}
				reportData = []auditor.AzureAuditorReportLine{}
				for _, line := range reportDataUnique {
					reportData = append(reportData, line)
				}

				// json encoding
				data, err := json.Marshal(reportData)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					/* #nosec G104 */
					w.Write([]byte(err.Error())) // nolint:errcheck
				}

				w.Header().Add("Content-Type", "application/json")
				/* #nosec G104 */
				w.Write(data) // nolint:errcheck
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})

	// config
	mux.HandleFunc(endpoints["config"], func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain")

		content, err := yaml.Marshal(azureAuditor.GetConfig())
		if err == nil {
			if _, writeErr := w.Write(content); writeErr != nil {
				logger.Error(writeErr)
			}
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			if _, writeErr := w.Write([]byte("Unable to marshal configuration")); writeErr != nil {
				logger.Error(writeErr)
			}
			logger.Error(err)
		}
	})

	mux.Handle(endpoints["metrics"], http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			azureAuditor.MetricsLock().RLock()
			defer azureAuditor.MetricsLock().RUnlock()
			tracing.RegisterAzureMetricAutoClean(promhttp.Handler()).ServeHTTP(w, r)
		},
	))

	srv := &http.Server{
		Addr:         Opts.Server.Bind,
		Handler:      mux,
		ReadTimeout:  Opts.Server.ReadTimeout,
		WriteTimeout: Opts.Server.WriteTimeout,
	}
	go func() {
		logger.Fatal(srv.ListenAndServe())
	}()
	// Setting up signal capturing
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Waiting for SIGINT (kill -2)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	logger.Fatal(srv.Shutdown(ctx))
}
