package main

import (
	"bufio"
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

			resp := writeSpreadsheetReport(v.Repository, v.Tag, ir, vuln, malw, sens)

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
	spreadsheetResp := writeSpreadsheetReport(image, tag, ir, vuln, malw, sens)
	htmlResp := writeHTMLReport(image, tag, ir, vuln, malw, sens)
	log.Println(htmlResp)
	var response = ImageResponse{image, tag, registry, spreadsheetResp}
	responseList = append(responseList, response)

	json.NewEncoder(w).Encode(responseList)
}

func writeSpreadsheetReport(image, tag string, ir ImageRisk, vuln ImageVulnerabilities, malw Malware, sens Sensitive) string {
	fileName := strings.Replace(image, "/", "_", -1)
	f := createSpreadsheet(fileName + "-" + tag)
	writeRisk(f, ir)
	writeVulnerabilities(f, vuln)
	writeMalware(f, malw)
	writeSensitive(f, sens)
	response := saveFile(f, fileName+"-"+tag)
	return response
}

func writeHTMLReport(image, tag string, ir ImageRisk, vuln ImageVulnerabilities, malw Malware, sens Sensitive) string {
	path := createHTMLFile(image, tag, ir.Registry)
	w, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	writer := bufio.NewWriter(w)
	// Start writing the raw HTML file
	/* writeHTMLOne(image, tag, ir.Registry, "assets/1.inc", writer, w)
	writeHTMLRisk(image, tag, ir, writer, w)
	writeHTMLOne(image, tag, ir.Registry, "assets/2.inc", writer, w)
	writeHTMLVulnerability(vuln, writer, w)
	writeHTMLOne(image, tag, ir.Registry, "assets/3.inc", writer, w)
	writeHTMLSensitive(sens, writer, w)
	writeHTMLOne(image, tag, ir.Registry, "assets/4.inc", writer, w)
	writeHTMLMalware(malw, writer, w)
	writeHTMLOne(image, tag, ir.Registry, "assets/5.inc", writer, w) */
	writeHTMLRiskv2("assets/risk1.inc", ir, writer, w)
	//Compliance SVG Check
	if ir.Disallowed {
		str := getSvgNonCompliant(ir)
		writer.WriteString(str)
	} else {
		str := getSvgCompliant(ir)
		writer.WriteString(str)
	}
	writeHTMLRiskv2("assets/risk2.inc", ir, writer, w)
	// Image Assurance if Non-Compliant
	if ir.Disallowed {
		writeHTMLRiskNonCompliant(ir, writer, w)
	}
	writeHTMLRiskv2("assets/risk3.inc", ir, writer, w)
	m := getResourceFromVuln(vuln)
	writeHTMLResource(m, writer, w)
	writeHTMLVulnerability(vuln, writer, w)
	writeHTMLRiskv2("assets/risk4.inc", ir, writer, w)
	writeHTMLSensitive(sens, writer, w)
	writeHTMLRiskv2("assets/risk5.inc", ir, writer, w)
	writeHTMLMalware(malw, writer, w)
	writeHTMLRiskv2("assets/risk6.inc", ir, writer, w)
	w.Close()
	log.Printf("Report for image: %s created successfully \n", image+":"+tag)
	return "HTML report created successfully"
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

		resp := writeSpreadsheetReport(image.Name, image.Tag, ir, vuln, malw, sens)
		var response = ImageResponse{image.Name, image.Tag, image.Registry, resp}
		responseList = append(responseList, response)
		i++
	}
	irList.Count = i
	irList.Response = responseList
	json.NewEncoder(w).Encode(irList)
}
