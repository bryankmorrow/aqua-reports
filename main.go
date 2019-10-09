package main

import (
	"log"
	"os"

	"github.com/BryanKMorrow/reports-v2/src/system/app"
)

func main() {
	// check for fatal, panic if true
	fatal := checkEnv()
	if fatal {
		log.Fatalln("Environment variables not set, stopping aqua-reports")
	}

	s := app.NewServer()
	port := os.Getenv("AQUA_REPORTS_PORT")
	s.Init(port)
	s.Start()
}

func checkEnv() bool {
	fatal := false
	// Get Environment Parameters and check for values
	url := os.Getenv("AQUA_URL")
	if url == "" {
		log.Println("Please set the AQUA_URL environment variable")
		fatal = true
	}
	user := os.Getenv("AQUA_USER")
	if user == "" {
		log.Println("Please set the AQUA_USER environment variable")
		fatal = true
	}
	password := os.Getenv("AQUA_PASSWORD")
	if password == "" {
		log.Println("Please set the AQUA_PASSWORD environment variable")
		fatal = true
	}
	port := os.Getenv("AQUA_REPORTS_PORT")
	if port == "" {
		log.Println("Please set the AQUA_REPORTS_PORT environment variable")
		fatal = true
	}
	return fatal
}
