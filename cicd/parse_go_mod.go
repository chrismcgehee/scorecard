package cicd

import (
	"fmt"
	"os"
	"path"
	"sync"

	"github.com/aquasecurity/go-dep-parser/pkg/gomod"
	"github.com/aquasecurity/go-dep-parser/pkg/types"

	"github.com/ossf/scorecard/cmd"
)

type GoModParser struct{}

func (g GoModParser) isSupported(filePath string) bool {
	return path.Base(filePath) == "go.sum"
}

func (g GoModParser) getDependencies(filePath string, dependenciesToIgnore []string) ([]Dependency, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	modules, err := gomod.Parse(f)
	if err != nil {
		return nil, err
	}
	resultsCh := make(chan Dependency)
	go getRepoInfo(modules, dependenciesToIgnore, resultsCh)
	dependencies := make([]Dependency, 0, len(modules))
	for dependency := range resultsCh {		
		dependencies = append(dependencies, dependency)
	}
	fmt.Println(dependencies)
	return dependencies, nil
}

func getRepoInfo(modules []types.Library, dependenciesToIgnore []string, resultsCh chan Dependency) {
	wg := sync.WaitGroup{}
	for _, module := range modules {
		if doIgnoreDependency(module.Name, dependenciesToIgnore) {
			// TODO mcgehee: log this
			continue
		}
		moduleName := module.Name
		wg.Add(1)
		go func() {
			defer wg.Done()
			repo, err := cmd.FetchGitRepositoryFromGoMod(moduleName)
			if err != nil {
				// TODO mcgehee: log this
				return
			}
			resultsCh <- Dependency{
				Name: moduleName,
				Repo: repo,
			}
		}()
	}
	wg.Wait()
	close(resultsCh)
}

func doIgnoreDependency(module string, dependenciesToIgnore []string) bool {
	for _, ignore := range dependenciesToIgnore {
		if module == ignore {
			return true
		}
	}
	return false
}
