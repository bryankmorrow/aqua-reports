package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {

	// Create Router
	r := mux.NewRouter().UseEncodedPath()

	// report for every image
	r.HandleFunc("/reports/all", getAllImages).Methods("GET")
	// report for singular report by registry, image name and tag
	r.HandleFunc("/report/{registry}/{image}/{tag}", getImage).Methods("GET")
	// report for every listed images in one report
	r.HandleFunc("/reports/images", getImagesFromPost).Methods("POST")

	http.ListenAndServe(":8000", r)
	log.Println("Listening on :8000")
}
