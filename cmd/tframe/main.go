package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	manifestPath := flag.String("manifest", "", "manifest file path (default: $HOME/.config/tframe.json)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: tframe get [options] tcp://host:port/path\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 || args[0] != "get" {
		flag.Usage()
		os.Exit(2)
	}

	path := *manifestPath
	if path == "" {
		var err error
		path, err = defaultManifestPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "tframe: resolve default manifest path: %v\n", err)
			os.Exit(1)
		}
	}

	m, err := loadManifest(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tframe: %v\n", err)
		os.Exit(1)
	}

	if err := doGetStdout(args[1], m); err != nil {
		fmt.Fprintf(os.Stderr, "tframe: %v\n", err)
		os.Exit(1)
	}
}
