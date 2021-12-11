// Copyright 2020 Security Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checks

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v3/checker"
	"github.com/ossf/scorecard/v3/checks/fileparser"
	sce "github.com/ossf/scorecard/v3/errors"
	"github.com/rhysd/actionlint"
)

// CheckPackaging is the registered name for Packaging.
const CheckPackaging = "Packaging"

//nolint:gochecknoinits
func init() {
	registerCheck(CheckPackaging, Packaging)
}

func isGithubWorkflowFile(filename string) (bool, error) {
	return strings.HasPrefix(strings.ToLower(filename), ".github/workflows"), nil
}

// Packaging runs Packaging check.
func Packaging(c *checker.CheckRequest) checker.CheckResult {
	matchedFiles, err := c.RepoClient.ListFiles(isGithubWorkflowFile)
	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("RepoClient.ListFiles: %v", err))
		return checker.CreateRuntimeErrorResult(CheckPackaging, e)
	}

	for _, fp := range matchedFiles {
		fc, err := c.RepoClient.GetFileContent(fp)
		if err != nil {
			e := sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("RepoClient.GetFileContent: %v", err))
			return checker.CreateRuntimeErrorResult(CheckPackaging, e)
		}

		workflow, errs := actionlint.Parse(fc)
		if len(errs) > 0 && workflow == nil {
			e := fileparser.FormatActionlintError(errs)
			return checker.CreateRuntimeErrorResult(CheckPackaging, e)
		}
		if !isPackagingWorkflow(workflow, fp, c.Dlogger) {
			continue
		}

		runs, err := c.RepoClient.ListSuccessfulWorkflowRuns(filepath.Base(fp))
		if err != nil {
			e := sce.WithMessage(sce.ErrScorecardInternal, fmt.Sprintf("Client.Actions.ListWorkflowRunsByFileName: %v", err))
			return checker.CreateRuntimeErrorResult(CheckPackaging, e)
		}
		if len(runs) > 0 {
			c.Dlogger.Info3(&checker.LogMessage{
				Path:   fp,
				Type:   checker.FileTypeSource,
				Offset: checker.OffsetDefault,
				Text:   fmt.Sprintf("GitHub publishing workflow used in run %s", runs[0].URL),
			})
			return checker.CreateMaxScoreResult(CheckPackaging,
				"publishing workflow detected")
		}
		c.Dlogger.Info3(&checker.LogMessage{
			Path:   fp,
			Type:   checker.FileTypeSource,
			Offset: checker.OffsetDefault,
			Text:   "GitHub publishing workflow not used in runs",
		})
	}

	c.Dlogger.Warn3(&checker.LogMessage{
		Text: "no GitHub publishing workflow detected",
	})

	return checker.CreateInconclusiveResult(CheckPackaging,
		"no published package detected")
}

type JobMatcher struct {
	uses    []string
	with    []map[string]string
	runs    []string
	logText string
}

func (m *JobMatcher) Matches(job *actionlint.Job) (bool, error) {

	usesNeedingMatch := m.uses
	runsNeedingMatch := m.runs

	for _, step := range job.Steps {
		uses := fileparser.GetUses(step)
		if uses != nil {
			for i, needingMatch := range usesNeedingMatch {
				if !strings.HasPrefix(uses.Value, needingMatch + "@") {
					continue
				}
				if m.with != nil {
					with := fileparser.GetWith(step)
					if with == nil {
						continue
					}
					val, ok := with.Value[m.with[i]["key"]]
				}
				// remove the match from the list
				usesNeedingMatch = append(usesNeedingMatch[:i], usesNeedingMatch[i+1:]...)
				break
			}
		}
	}
}

// A packaging workflow.
func isPackagingWorkflow(workflow *actionlint.Workflow, fp string, dl checker.DetailLogger) (bool, error) {
	jobMatchers := []JobMatcher{
		JobMatcher{
			uses: []string {
				"actions/setup-node",
			},
			with: []map[string]string{
				{"registry-url": "https://registry.npmjs.org"},
			},
			runs: []string{
				"npm.*publish",
			},
			logText: "candidate node publishing workflow using npm",
		},
		JobMatcher{
			uses: []string {
				"actions/setup-java",
			},
			runs: []string{
				"mvn.*deploy",
			},
			logText: "candidate java publishing workflow using maven",
		},
		JobMatcher{
			uses: []string {
				"actions/setup-java",
			},
			runs: []string{
				"gradle.*publish",
			},
			logText: "candidate java publishing workflow using gradle",
		},
		JobMatcher{
			runs: []string{
				"gem.*push",
			},
			logText: "candidate ruby publishing workflow using gem",
		},
		JobMatcher{
			runs: []string{
				"nuget.*push",
			},
			logText: "candidate nuget publishing workflow",
		},
		JobMatcher{
			runs: []string{
				"docker.*push",
			},
			logText: "candidate docker publishing workflow",
		},
		JobMatcher{
			uses: []string{
				"docker/build-push-action",
			},
			logText: "candidate docker publishing workflow",
		},
		JobMatcher{
			uses: []string{
				"actions/setup-python",
				"pypa/gh-action-pypi-publish",
			},
			logText: "candidate python publishing workflow using pypi",
		},
		JobMatcher{
			uses: []string{
				"actions/setup-go",
				"goreleaser/goreleaser-action",
			},
			logText: "candidate golang publishing workflow",
		},
		JobMatcher{
			runs: []string{
				"cargo.*publish",
			},
			logText: "candidate rust publishing workflow using cargo",
		},
	}

	for _, job := range workflow.Jobs {
		for _, matcher := range jobMatchers {
			isMatch, err := matcher.Matches(job)
			if err != nil {
				return false, err
			}
			if !isMatch {
				continue
			}

			dl.Info3(&checker.LogMessage{
				Path:   fp,
				Type:   checker.FileTypeSource,
				Offset: fileparser.GetLineNumber(job.Pos),
				Text:   matcher.logText,
			})
			return true, nil
		}
	}



	// Nodejs packages.
	if strings.Contains(s, "actions/setup-node@") {
		r1 := regexp.MustCompile(`(?s)registry-url.*https://registry\.npmjs\.org`)
		r2 := regexp.MustCompile(`(?s)npm.*publish`)

		if r1.MatchString(s) && r2.MatchString(s) {
			dl.Info3(&checker.LogMessage{
				Path: fp,
				Type: checker.FileTypeSource,
				// Source file must have line number > 0.
				Offset: 1,
				Text:   "candidate node publishing workflow using npm",
			})
			return true
		}
	}

	// Java packages.
	if strings.Contains(s, "actions/setup-java@") {
		// Java packages with maven.
		r1 := regexp.MustCompile(`(?s)mvn.*deploy`)
		if r1.MatchString(s) {
			dl.Info3(&checker.LogMessage{
				Path: fp,
				Type: checker.FileTypeSource,
				// Source file must have line number > 0.
				Offset: 1,
				Text:   "candidate java publishing workflow using maven",
			})
			return true
		}

		// Java packages with gradle.
		r2 := regexp.MustCompile(`(?s)gradle.*publish`)
		if r2.MatchString(s) {
			dl.Info3(&checker.LogMessage{
				Path: fp,
				Type: checker.FileTypeSource,
				// Source file must have line number > 0.
				Offset: 1,
				Text:   "candidate java publishing workflow using gradle",
			})
			return true
		}
	}

	// Ruby packages.
	r := regexp.MustCompile(`(?s)gem.*push`)
	if r.MatchString(s) {
		dl.Info3(&checker.LogMessage{
			Path: fp,
			Type: checker.FileTypeSource,
			// Source file must have line number > 0.
			Offset: 1,
			Text:   "candidate ruby publishing workflow using gem",
		})
		return true
	}

	// NuGet packages.
	r = regexp.MustCompile(`(?s)nuget.*push`)
	if r.MatchString(s) {
		dl.Info3(&checker.LogMessage{
			Path: fp,
			Type: checker.FileTypeSource,
			// Source file must have line number > 0.
			Offset: 1,
			Text:   "candidate nuget publishing workflow",
		})
		return true
	}

	// Docker packages.
	if strings.Contains(s, "docker/build-push-action@") {
		dl.Info3(&checker.LogMessage{
			Path: fp,
			Type: checker.FileTypeSource,
			// Source file must have line number > 0.
			Offset: 1,
			Text:   "candidate docker publishing workflow",
		})
		return true
	}

	r = regexp.MustCompile(`(?s)docker.*push`)
	if r.MatchString(s) {
		dl.Info3(&checker.LogMessage{
			Path: fp,
			Type: checker.FileTypeSource,
			// Source file must have line number > 0.
			Offset: 1,
			Text:   "candidate docker publishing workflow",
		})
		return true
	}

	// Python packages.
	if strings.Contains(s, "actions/setup-python@") && strings.Contains(s, "pypa/gh-action-pypi-publish@master") {
		dl.Info3(&checker.LogMessage{
			Path: fp,
			Type: checker.FileTypeSource,
			// Source file must have line number > 0.
			Offset: 1,
			Text:   "candidate python publishing workflow using pypi",
		})
		return true
	}

	// Go packages.
	if strings.Contains(s, "actions/setup-go") &&
		strings.Contains(s, "goreleaser/goreleaser-action@") {
		dl.Info3(&checker.LogMessage{
			Path: fp,
			Type: checker.FileTypeSource,
			// Source file must have line number > 0.
			Offset: 1,
			Text:   "candidate golang publishing workflow",
		})
		return true
	}

	// Rust packages.
	// https://doc.rust-lang.org/cargo/reference/publishing.html.
	r = regexp.MustCompile(`(?s)cargo.*publish`)
	if r.MatchString(s) {
		dl.Info3(&checker.LogMessage{
			Path: fp,
			Type: checker.FileTypeSource,
			// Source file must have line number > 0.
			Offset: 1,
			Text:   "candidate rust publishing workflow using cargo",
		})
		return true
	}

	dl.Debug3(&checker.LogMessage{
		Path: fp,
		Type: checker.FileTypeSource,
		// Source file must have line number > 0.
		Offset: 1,
		Text:   "not a publishing workflow",
	})
	return false
}
