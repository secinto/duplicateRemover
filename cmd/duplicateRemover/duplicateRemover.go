package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/secinto/duplicateRemover/remover"
)

func main() {
	// Parse the command line flags and read config files
	options := remover.ParseOptions()

	newRemover, err := remover.NewRemover(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create pusher: %s\n", err)
	}

	err = newRemover.Remove()
	if err != nil {
		gologger.Fatal().Msgf("Could not push: %s\n", err)
	}
}
