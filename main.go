package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	// Web UI mode — port is selected in the browser.
	if err := RunWebUI(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		log.Fatal(err)
	}
}
