package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	port := flag.String("port", "", "COM port to monitor (e.g. COM3). Empty = all USB serial ports.")
	verbose := flag.Bool("v", false, "Show all USB transfer events, not just data")
	noColor := flag.Bool("no-color", false, "Disable ANSI color output")
	flag.Parse()

	if !isAdmin() {
		fmt.Fprintln(os.Stderr, "Error: Administrator privileges are required to capture ETW events.")
		os.Exit(1)
	}

	cfg := Config{
		Port:    *port,
		Verbose: *verbose,
		Color:   !*noColor,
	}

	sniffer, err := NewSniffer(cfg)
	if err != nil {
		log.Fatalf("init: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n[stopping]")
		sniffer.Close()
	}()

	printBanner(cfg)
	if err := sniffer.Run(); err != nil {
		log.Fatalf("run: %v", err)
	}
}

func printBanner(cfg Config) {
	target := "all USB virtual COM ports"
	if cfg.Port != "" {
		target = cfg.Port
	}
	fmt.Printf("USB Virtual COM Sniffer  —  monitoring %s\n", target)
	fmt.Println("Requires Administrator. Press Ctrl+C to stop.")
	fmt.Println("─────────────────────────────────────────────────")
}
