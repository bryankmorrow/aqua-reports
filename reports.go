package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/mux"
)

// ImageResponse for returning status of report creation
type ImageResponse struct {
	Name     string `json:"image"`
	Tag      string `json:"tag"`
	Registry string `json:"registry"`
}

func getAllImages(w http.ResponseWriter, r *http.Request) {
	log.Println("/reports/all route called")
	w.Header().Set("Content-Type", "application/json")
	var responseList []ImageResponse

	// Get Environment Parameters
	var csp Aqua
	csp.url = os.Getenv("AQUA_URL")
	csp.user = os.Getenv("AQUA_USER")
	csp.password = os.Getenv("AQUA_PASSWORD")
	csp.token = connectCSP()

	list := allImages(csp)

	for _, l := range list {
		for _, v := range l.Result {
			var response = ImageResponse{v.Repository, v.Tag, v.Registry}
			responseList = append(responseList, response)
			ir := imageRisk(csp, v.Registry, v.Repository, v.Tag)
			vuln := imageVulnerabilities(csp, v.Registry, v.Repository, v.Tag)
			sens := imageSensitive(csp, v.Registry, v.Repository, v.Tag)
			malw := imageMalware(csp, v.Registry, v.Repository, v.Tag)

			writeReport(v.Repository, v.Tag, ir, vuln, malw, sens)
			log.Println(response)
		}
	}

	json.NewEncoder(w).Encode(responseList)
}

func getImage(w http.ResponseWriter, r *http.Request) {
	// Get Environment Parameters
	var csp Aqua
	csp.url = os.Getenv("AQUA_URL")
	csp.user = os.Getenv("AQUA_USER")
	csp.password = os.Getenv("AQUA_PASSWORD")
	csp.token = connectCSP()

	log.Println("/reports/image route called")
	w.Header().Set("Content-Type", "application/json")
	var responseList []ImageResponse

	params := mux.Vars(r)
	encodedRegistry := params["registry"]
	registry, err := url.QueryUnescape(encodedRegistry)
	if err != nil {
		log.Fatal(err)
		return
	}
	encodedImage := params["image"]
	image, err := url.QueryUnescape(encodedImage)
	if err != nil {
		log.Fatal(err)
		return
	}
	encodedTag := params["tag"]
	tag, err := url.QueryUnescape(encodedTag)
	if err != nil {
		log.Fatal(err)
		return
	}

	var response = ImageResponse{image, tag, registry}
	responseList = append(responseList, response)

	ir := imageRisk(csp, registry, image, tag)
	vuln := imageVulnerabilities(csp, registry, image, tag)
	sens := imageSensitive(csp, registry, image, tag)
	malw := imageMalware(csp, registry, image, tag)

	writeReport(image, tag, ir, vuln, malw, sens)

	log.Println(response)
	json.NewEncoder(w).Encode(responseList)
}

func writeReport(image, tag string, ir ImageRisk, vuln ImageVulnerabilities, malw Malware, sens Sensitive) {
	fileName := strings.Replace(image, "/", "_", -1)
	f := createSpreadsheet(fileName + "-" + tag)
	writeRisk(f, ir)
	writeVulnerabilities(f, vuln)
	writeMalware(f, malw)
	writeSensitive(f, sens)
	saveFile(f, fileName+"-"+tag)
}

func getImagesFromPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var csp Aqua
	csp.url = os.Getenv("AQUA_URL")
	csp.user = os.Getenv("AQUA_USER")
	csp.password = os.Getenv("AQUA_PASSWORD")
	csp.token = connectCSP()

	log.Println("/reports/images post route called")

	var images []ImageResponse
	_ = json.NewDecoder(r.Body).Decode(&images)
	for _, image := range images {
		ir := imageRisk(csp, image.Registry, image.Name, image.Tag)
		vuln := imageVulnerabilities(csp, image.Registry, image.Name, image.Tag)
		sens := imageSensitive(csp, image.Registry, image.Name, image.Tag)
		malw := imageMalware(csp, image.Registry, image.Name, image.Tag)

		writeReport(image.Name, image.Tag, ir, vuln, malw, sens)
	}
	json.NewEncoder(w).Encode(&images)
}
