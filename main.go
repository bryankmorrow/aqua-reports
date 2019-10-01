package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {
	// check for fatal, panic if true
	fatal := checkEnv()
	if fatal {
		log.Fatalln("Environment variables not set, stopping aqua-reports")
	}

	// Create Router
	r := mux.NewRouter().UseEncodedPath()

	// report for every image
	r.HandleFunc("/reports/all", getAllImages).Methods("GET")
	// report for singular report by registry, image name and tag
	r.HandleFunc("/report/{registry}/{image}/{tag}", getImage).Methods("GET")
	// report for every listed images in one report
	r.HandleFunc("/reports/images", getImagesFromPost).Methods("POST")

	http.ListenAndServe(":8001", r)
	log.Println("Listening on :8001")
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
	return fatal
}
