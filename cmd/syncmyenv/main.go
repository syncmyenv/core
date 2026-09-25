package main

import (
	"os"

	"github.com/syncmyenv/core/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
