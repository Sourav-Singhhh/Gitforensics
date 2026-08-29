package main

import (
	"fmt"
	"os"
)

const Version = "0.1.0-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("gitforensics %s\n", Version)
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, "gitforensics: forensic Git object scanner (Phase 1)")
	os.Exit(0)
}
