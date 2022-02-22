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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/checks/evaluation"
	"github.com/ossf/scorecard/v4/checks/raw"
	"github.com/ossf/scorecard/v4/clients/githubrepo"
	sce "github.com/ossf/scorecard/v4/errors"
)

// CheckSecurityAudit is the registred name for Security-Audit.
const CheckSecurityAudit = "Security-Audit"

//nolint:gochecknoinits
func init() {
	if err := registerCheck(CheckSecurityAudit, SecurityAudit, nil); err != nil {
		// This should never happen.
		panic(err)
	}
}

// SecurityAudit checks to see if a security review has been done for this project.
func SecurityAudit(c *checker.CheckRequest) checker.CheckResult {
	rawData, err := raw.SecurityPolicy(c)
	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, err.Error())
		return checker.CreateRuntimeErrorResult(CheckSecurityPolicy, e)
	}

	// Set the raw results.
	if c.RawResults != nil {
		c.RawResults.SecurityPolicyResults = rawData
		return checker.CheckResult{}
	}

	return evaluation.SecurityPolicy(CheckSecurityPolicy, c.Dlogger, &rawData)
}

// Download security-reviews repo if it's not present locally.
func downloadSecurityReviews(c *checker.CheckRequest) error {
	// Get the HEAD commit SHA.
	graphqlHandler := githubrepo.GraphqlHandler2{}
	graphqlHandler.Init(c.Ctx, "ossf", "security-reviews")
	if err := graphqlHandler.Setup(); err != nil {
		return err
	}
	// TODO cmcgehee: Check if this will work for cron.
	repoBaseDir := path.Join(os.TempDir(), "security-reviews-repo-for-scorecard")
	repoShaDir := path.Join(repoBaseDir, graphqlHandler.LastCommitDefaultBranch)
	_, err := os.Stat(repoShaDir)
	if errors.Is(err, fs.ErrNotExist) {
		// Delete the directory.
		if err := os.RemoveAll(repoBaseDir); err != nil {
			return err
		}
		if err := os.MkdirAll(repoShaDir, os.ModePerm); err != nil {
			return err
		}
		

	} else if err != nil {
		return err
	}



	return nil
}
