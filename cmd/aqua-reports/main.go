package main

import (
	"log"
	"os"
	"strconv"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
	"github.com/BryanKMorrow/aqua-reports/src/system/app"
	"github.com/BryanKMorrow/aqua-reports/src/system/aqua"
)

func main() {
	var port string
	// check if command line or container
	if app.ModeFlag == "cli" {
		log.Println("Using command line flags")
		fatal := checkFlag()
		if fatal {
			log.Fatalln("Command line arguments are not set, stopping aqua-reports")
		}
		// version 1
		aqua.Mode = app.ModeFlag
		aqua.URL = app.URLFlag
		aqua.User = app.UserFlag
		aqua.Password = app.PasswordFlag
		// version 2
		reports.Mode = app.ModeFlag
		reports.URL = app.URLFlag
		reports.User = app.UserFlag
		reports.Password = app.PasswordFlag
		port = strconv.Itoa(app.PortFlag)
	} else if app.ModeFlag == "container" {
		log.Println("Using the environment variables")
		fatal := checkEnv()
		if fatal {
			log.Fatalln("Environment variables not set, stopping aqua-reports")
		}
		port = os.Getenv("AQUA_REPORTS_PORT")
	} else {
		log.Fatalln("Command Line argument 'mode' not set to value of cli or container")
	}

	s := app.NewServer()

	s.Init(port)
	s.Start()
}

func checkFlag() bool {
	fatal := false
	if app.URLFlag == "" {
		log.Println("Please set the url argument to the Aqua CSP address")
		fatal = true
	}
	if app.UserFlag == "" {
		log.Println("Please set the user argument to the Aqua CSP user with API access")
		fatal = true
	}
	if app.PasswordFlag == "" {
		log.Println("Please set the password argument for the Aqua CSP API access user")
		fatal = true
	}
	if app.PortFlag == 0 {
		log.Println("Please set the port argument for this application")
		fatal = true
	}
	return fatal
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
