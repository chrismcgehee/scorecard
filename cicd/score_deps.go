package cicd

import "fmt"

func ScoreDeps() {
	options, err := readConfig()
	if err != nil {
		panic(err)
	}
	fmt.Println(options)
	doParse()
}
