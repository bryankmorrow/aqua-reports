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

// ImageResponseList for returning  all report status
type ImageResponseList struct {
	Count    int             `json:"count,omitempty"`
	Response []ImageResponse `json:"response"`
}

// ImageResponse for returning status of report creation
type ImageResponse struct {
	Name        string `json:"image"`
	Tag         string `json:"tag"`
	Registry    string `json:"registry"`
	WriteStatus string `json:"write-status,omitempty"`
}

func getAllImages(w http.ResponseWriter, r *http.Request) {
	log.Println("/reports/all route called")
	w.Header().Set("Content-Type", "application/json")
	var irList ImageResponseList
	var responseList []ImageResponse
	i := 1

	// Get Environment Parameters
	var csp Aqua
	csp.url = os.Getenv("AQUA_URL")
	csp.user = os.Getenv("AQUA_USER")
	csp.password = os.Getenv("AQUA_PASSWORD")
	csp.token = connectCSP()

	list := allImages(csp)

	for _, l := range list {
		for _, v := range l.Result {
			ir := imageRisk(csp, v.Registry, v.Repository, v.Tag)
			vuln := imageVulnerabilities(csp, v.Registry, v.Repository, v.Tag)
			sens := imageSensitive(csp, v.Registry, v.Repository, v.Tag)
			malw := imageMalware(csp, v.Registry, v.Repository, v.Tag)

			resp := writeReport(v.Repository, v.Tag, ir, vuln, malw, sens)

			var response = ImageResponse{v.Repository, v.Tag, v.Registry, resp}
			responseList = append(responseList, response)
			i++
		}
	}
	irList.Count = i
	irList.Response = responseList
	json.NewEncoder(w).Encode(irList)
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

	ir := imageRisk(csp, registry, image, tag)
	vuln := imageVulnerabilities(csp, registry, image, tag)
	sens := imageSensitive(csp, registry, image, tag)
	malw := imageMalware(csp, registry, image, tag)

	resp := writeReport(image, tag, ir, vuln, malw, sens)

	var response = ImageResponse{image, tag, registry, resp}
	responseList = append(responseList, response)

	log.Println(response)
	json.NewEncoder(w).Encode(responseList)
}

func writeReport(image, tag string, ir ImageRisk, vuln ImageVulnerabilities, malw Malware, sens Sensitive) string {
	fileName := strings.Replace(image, "/", "_", -1)
	f := createSpreadsheet(fileName + "-" + tag)
	writeRisk(f, ir)
	writeVulnerabilities(f, vuln)
	writeMalware(f, malw)
	writeSensitive(f, sens)
	response := saveFile(f, fileName+"-"+tag)
	return response
}

func getImagesFromPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var csp Aqua
	csp.url = os.Getenv("AQUA_URL")
	csp.user = os.Getenv("AQUA_USER")
	csp.password = os.Getenv("AQUA_PASSWORD")
	csp.token = connectCSP()

	log.Println("/reports/images post route called")
	var imageList []ImageResponse
	var irList ImageResponseList
	var responseList []ImageResponse
	i := 1
	_ = json.NewDecoder(r.Body).Decode(&imageList)
	for _, image := range imageList {
		ir := imageRisk(csp, image.Registry, image.Name, image.Tag)
		vuln := imageVulnerabilities(csp, image.Registry, image.Name, image.Tag)
		sens := imageSensitive(csp, image.Registry, image.Name, image.Tag)
		malw := imageMalware(csp, image.Registry, image.Name, image.Tag)

		resp := writeReport(image.Name, image.Tag, ir, vuln, malw, sens)
		var response = ImageResponse{image.Name, image.Tag, image.Registry, resp}
		responseList = append(responseList, response)
		i++
	}
	irList.Count = i
	irList.Response = responseList
	json.NewEncoder(w).Encode(irList)
}
