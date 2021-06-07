package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ossf/scorecard/cicd"
)


func main() {
	failures, err := cicd.ScoreDeps()
	if err != nil {
		fmt.Println(err)
        os.Exit(2)
	}
	if len(failures) > 0 {
		fmt.Printf("Checks for dependencies failed:\n%s\n", strings.Join(failures, "\n"))
        os.Exit(1)
	}

	os.Exit(0)
}