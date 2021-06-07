package cicd

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/google/go-github/v32/github"
	"github.com/shurcooL/githubv4"
	"go.uber.org/zap"

	"github.com/ossf/scorecard/checks"
	"github.com/ossf/scorecard/pkg"
	"github.com/ossf/scorecard/repos"
	"github.com/ossf/scorecard/roundtripper"
)

var logLevel = zap.InfoLevel

type Dependency struct {
	// Name is the canonical name of the dependency.
	Name string
	// Repo is the location of the repository for the source code for the dependency.
	Repo string
}

type DepParser interface {
	isSupported(filePath string) bool
	getDependencies(filePath string, dependenciesToIgnore []string) ([]Dependency, error)
}

func ScoreDeps() ([]string, error) {
	failures := make([]string, 0)
	path := "/home/chris/code/ossf/aqua-dep/go.sum"
	options, err := readConfig()
	if err != nil {
		return failures, err
	}
	fmt.Println(options)

	parsers := []DepParser{
		GoModParser{},
	}
	var depParser DepParser
	for _, parser := range parsers {
		if parser.isSupported(path) {
			depParser = parser
			break
		}
	}
	if depParser == nil {
		// TODO mcgehee: log this
		return failures, nil
	}

	dependencies, err := depParser.getDependencies(path, options.IgnoreDependencies)
	if err != nil {
		return failures, err
	}
	// TODO mcgehee: Use goroutine
	for _, dependency := range dependencies {
		fmt.Println(dependency)

		repoURL := repos.RepoURL{}
		if err := repoURL.Set(dependency.Repo); err != nil {
			// return fmt.Errorf("error setting RepoURL: %w", err)
			// TODO mcgehee: log this
		}
		if err := repoURL.ValidGitHubURL(); err != nil {
			continue
		}

		cfg := zap.NewProductionConfig()
		cfg.Level.SetLevel(logLevel)
		logger, err := cfg.Build()
		if err != nil {
			log.Fatalf("unable to construct logger: %v", err)
		}
		// nolint
		defer logger.Sync() // flushes buffer, if any
		sugar := logger.Sugar()
		ctx := context.Background()
		rt := roundtripper.NewTransport(ctx, sugar)
		httpClient := &http.Client{
			Transport: rt,
		}
		githubClient := github.NewClient(httpClient)
		graphClient := githubv4.NewClient(httpClient)
		repoResult := pkg.RunScorecards(ctx, repoURL, checks.AllChecks, httpClient, githubClient, graphClient)
		if repoResult.Score < options.MinScore {
			failures = append(failures, fmt.Sprintf("Score of %d for %s is below the minimum score of %d.",
				repoResult.Score, dependency.Name, options.MinScore))
		} else {
			fmt.Println(dependency.Name, repoResult.Score)
		}
		for _, requiredCheck := range options.RequiredChecks {
			for _, checkResult := range repoResult.Checks {
				if requiredCheck.Name != checkResult.Name {
					continue
				}
				if requiredCheck.Confidence < checkResult.Confidence {
					continue
				}
				if !checkResult.Pass {
					failures = append(failures, fmt.Sprintf("Required check %s did not pass for %s (confidence %d).",
						checkResult.Name, dependency.Name, checkResult.Confidence))
				}
			}
		}
	}

	return failures, nil
}
