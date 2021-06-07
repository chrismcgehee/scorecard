package cicd

import (
	"os"

	"gopkg.in/yaml.v2"
)

type ConfigOptions struct {
	MinScore       int `yaml:"min_score"`
	RequiredChecks []struct {
		Name       string `yaml:"name"`
		Confidence int    `yaml:"confidence"`
	} `yaml:"required_checks"`
	IgnoreDependencies []string `yaml:"ignore_dependencies"`
}

func readConfig() (ConfigOptions, error) {
	var options ConfigOptions
	fileContents, err := os.ReadFile("/home/chris/code/ossf/scorecard/cicd/config.yaml")
	if err != nil {
		return options, err
	}
	err = yaml.Unmarshal(fileContents, &options)
	if err != nil {
		return options, err
	}

	return options, nil
}
