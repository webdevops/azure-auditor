package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"runtime"
	"strings"

	sprig "github.com/Masterminds/sprig/v3"
	"github.com/google/uuid"
	flags "github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/webdevops/go-common/prometheus/azuretracing"
	yaml "gopkg.in/yaml.v3"

	auditor "github.com/webdevops/azure-auditor/auditor"
	"github.com/webdevops/azure-auditor/config"
)

const (
	Author = "webdevops.io"

	UserAgent = "azure-auditor/"
)

var (
	argparser *flags.Parser
	opts      config.Opts

	audit *auditor.AzureAuditor

	// Git version information
	gitCommit = "<unknown>"
	gitTag    = "<unknown>"
)

func main() {
	initArgparser()
	initLogger()

	log.Infof("starting azure-auditor v%s (%s; %s; by %v)", gitTag, gitCommit, runtime.Version(), Author)
	log.Info(string(opts.GetJson()))

	log.Infof("starting audit")
	audit = auditor.NewAzureAuditor()
	audit.Opts = opts
	audit.UserAgent = UserAgent + gitTag
	audit.ParseConfig(opts.Config...)
	audit.Run()

	log.Infof("Starting http server on %s", opts.ServerBind)
	startHttpServer()
}

func initArgparser() {
	argparser = flags.NewParser(&opts, flags.Default)
	_, err := argparser.Parse()

	// check if there is an parse error
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			fmt.Println()
			argparser.WriteHelp(os.Stdout)
			os.Exit(1)
		}
	}
}

func initLogger() {
	// verbose level
	if opts.Logger.Debug {
		log.SetLevel(log.DebugLevel)
	}

	// trace level
	if opts.Logger.Trace {
		log.SetReportCaller(true)
		log.SetLevel(log.TraceLevel)
		log.SetFormatter(&log.TextFormatter{
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				s := strings.Split(f.Function, "/")
				funcName := s[len(s)-1]
				return funcName, fmt.Sprintf("%s:%d", f.File, f.Line)
			},
		})
	}

	// json log format
	if opts.Logger.Json {
		log.SetReportCaller(true)
		log.SetFormatter(&log.JSONFormatter{
			DisableTimestamp: true,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				s := strings.Split(f.Function, "/")
				funcName := s[len(s)-1]
				return funcName, fmt.Sprintf("%s:%d", f.File, f.Line)
			},
		})
	}
}

// start and handle prometheus handler
func startHttpServer() {
	// healthz
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprint(w, "Ok"); err != nil {
			log.Error(err)
		}
	})

	// readyz
	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprint(w, "Ok"); err != nil {
			log.Error(err)
		}
	})

	// report
	reportTmpl, err := template.New("report").Funcs(template.FuncMap{
		"toYaml": func(obj interface{}) string {
			out, _ := yaml.Marshal(obj)
			return string(out)
		},
		"raw": func(val string) template.HTML {
			return template.HTML(val)
		},
	}).Funcs(sprig.HtmlFuncMap()).ParseGlob("./templates/report.html")
	if err != nil {
		log.Panic(err)
	}
	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		cspNonce := base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))

		w.Header().Add("Content-Type", "text/html")
		w.Header().Add("Referrer-Policy", "same-origin")
		w.Header().Add("X-Frame-Options", "DENY")
		w.Header().Add("X-XSS-Protection", "1; mode=block")
		w.Header().Add("X-Content-Type-Options", "nosniff")
		w.Header().Add("Content-Security-Policy",
			fmt.Sprintf(
				"default-src 'self'; script-src-elem 'nonce-%[1]s'; style-src 'nonce-%[1]s' unsafe-inline; img-src 'self' data:",
				cspNonce,
			),
		)

		content, err := yaml.Marshal(audit.GetConfig())
		if err != nil {
			log.Error(err)
		}

		templatePayload := struct {
			Nonce         string
			Config        string
			Report        map[string]*auditor.AzureAuditorReport
			RequestReport string
		}{
			Nonce:         cspNonce,
			Config:        string(content),
			Report:        audit.GetReport(),
			RequestReport: r.URL.Query().Get("report"),
		}

		if err := reportTmpl.ExecuteTemplate(w, "report.html", templatePayload); err != nil {
			log.Error(err)
		}
	})

	http.HandleFunc("/report/data", func(w http.ResponseWriter, r *http.Request) {
		if reportName := r.URL.Query().Get("report"); reportName != "" {
			reportList := audit.GetReport()
			if report, ok := reportList[reportName]; ok {
				data, err := json.Marshal(report.Lines)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(err.Error()))
				}

				w.Header().Add("Content-Type", "application/json")
				w.Write(data)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})

	// config
	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain")

		content, err := yaml.Marshal(audit.GetConfig())
		if err == nil {
			if _, writeErr := w.Write(content); writeErr != nil {
				log.Error(writeErr)
			}
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			if _, writeErr := w.Write([]byte("Unable to marshal configuration")); writeErr != nil {
				log.Error(writeErr)
			}
			log.Error(err)
		}
	})

	http.Handle("/metrics", azuretracing.RegisterAzureMetricAutoClean(promhttp.Handler()))
	log.Error(http.ListenAndServe(opts.ServerBind, nil))
}
