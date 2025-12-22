package main

import (
	"fmt"
	"os"

	"github.com/webdevops/go-common/version"
)

var (
	// Git version information
	gitCommit = "<unknown>"
	gitTag    = "<unknown>"
	buildDate = "<unknown>"
)

func printStartup(app, author string) {
	appVersion := version.New(
		version.WithApp(app),
		version.WithAuthor(author),
		version.WithVersion(gitTag),
		version.WithGitCommit(gitCommit),
		version.WithBuildDate(buildDate),
	)

	if Opts.Version.Version {
		fmt.Println(appVersion.BuildVersionLine(Opts.Version.Template))
		os.Exit(0)
	}

	logger.Info(appVersion.Title(nil))
	logger.Info(string(Opts.GetJson()))
}
