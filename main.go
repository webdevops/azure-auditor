package main

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/webdevops/go-prometheus-common/azuretracing"
	"gopkg.in/yaml.v3"

	auditor "github.com/webdevops/azure-audit-exporter/auditor"
	"github.com/webdevops/azure-audit-exporter/config"
)

const (
	Author = "webdevops.io"

	UserAgent = "azure-audit-exporter/"
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

	log.Infof("starting azure-audit-exporter v%s (%s; %s; by %v)", gitTag, gitCommit, runtime.Version(), Author)
	log.Info(string(opts.GetJson()))

	log.Infof("starting audit")
	audit = auditor.NewAzureAuditor()
	audit.Opts = opts
	audit.UserAgent = UserAgent + gitTag
	audit.ParseConfig(opts.Config)
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
			fmt.Println(err)
			fmt.Println()
			argparser.WriteHelp(os.Stdout)
			os.Exit(1)
		}
	}

	// verbose level
	if opts.Logger.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	// debug level
	if opts.Logger.Debug {
		log.SetReportCaller(true)
		log.SetLevel(log.TraceLevel)
		log.SetFormatter(&log.TextFormatter{
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				s := strings.Split(f.Function, ".")
				funcName := s[len(s)-1]
				return funcName, fmt.Sprintf("%s:%d", path.Base(f.File), f.Line)
			},
		})
	}

	// json log format
	if opts.Logger.LogJson {
		log.SetReportCaller(true)
		log.SetFormatter(&log.JSONFormatter{
			DisableTimestamp: true,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				s := strings.Split(f.Function, ".")
				funcName := s[len(s)-1]
				return funcName, fmt.Sprintf("%s:%d", path.Base(f.File), f.Line)
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

	// report
	reportTmpl := template.Must(template.ParseFiles("./templates/report.html"))
	http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		cspNonce := base64.StdEncoding.EncodeToString([]byte(uuid.New().String()))

		w.Header().Add("Content-Type", "text/html")
		w.Header().Add("Referrer-Policy", "same-origin")
		w.Header().Add("X-Frame-Options", "DENY")
		w.Header().Add("X-XSS-Protection", "1; mode=block")
		w.Header().Add("X-Content-Type-Options", "nosniff")
		w.Header().Add("Content-Security-Policy",
			fmt.Sprintf(
				"default-src 'self'; script-src-elem 'nonce-%[1]s'; style-src 'nonce-%[1]s'; img-src 'self' data:",
				cspNonce,
			),
		)

		content, err := yaml.Marshal(audit.GetConfig())
		if err != nil {
			log.Error(err)
		}

		templatePayload := struct {
			Nonce  string
			Config string
			Report map[string]*auditor.AzureAuditorReport
		}{
			Nonce:  cspNonce,
			Config: string(content),
			Report: audit.GetReport(),
		}

		if err := reportTmpl.Execute(w, templatePayload); err != nil {
			log.Error(err)
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
