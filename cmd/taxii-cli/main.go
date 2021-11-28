package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/shellcromancer/cti-go/pkg/stix"
	"github.com/shellcromancer/cti-go/pkg/taxii"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:     "taxii-cli",
		Short:   "taxii-cli is a tool for interacting with taxii servers.",
		Version: "0.0 --HEAD",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
)

func main() {
	flag.Parse()

	err := rootCmd.Execute()
	if err != nil {
		log.Fatalln(err)
	}

	taxiiClient, err := taxii.NewClient(
	// taxii.WithServer(*serverPtr),
	// taxii.WithVersion(*versionPtr),
	)
	if err != nil {
		log.Fatalln(err)
	}

	discovered, err := taxiiClient.Discovery()
	if err != nil {
		log.Fatalln(err)
	}

	var bundle stix.Bundle

	for _, root := range discovered.APIRoots {
		collections, err := taxiiClient.ListCollections(root)
		if err != nil {
			panic(err)
		}

		for _, collection := range collections {
			if collection.Title == "Enterprise ATT&CK" {
				bundle, err = taxiiClient.GetObjects(root, collection.ID)
				if err != nil {
					panic(err)
				}
			}
		}
	}

	out, err := json.Marshal(bundle)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(out))
}
