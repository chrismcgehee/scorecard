package cicd

import (
	"fmt"
	"os"

	"github.com/aquasecurity/go-dep-parser/pkg/gomod"

	"github.com/ossf/scorecard/cmd"
)

func doParse() ([]string, error) {
	f, err := os.Open("/home/chris/code/ossf/aqua-dep/go.sum")
	if err != nil {
		return nil, err
	}
	modules, err := gomod.Parse(f)
	if err != nil {
		return nil, err
	}
	repos := make([]string, 0, len(modules))
	for _, module := range modules {
		repo, err := cmd.FetchGitRepositoryFromGoMod(module.Name)
		if err != nil {
			// TODO mcgehee: log this
			continue
		}
		repos = append(repos, repo)
	}
	fmt.Println(repos)
	return repos, nil
}
