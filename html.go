package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

var template = "assets/template.html"

func createHTMLFile(image, tag, registry string) string {
	fileName := registry + "-" + strings.Replace(image, "/", "_", -1) + "-" + tag + ".html"
	err := os.Remove("reports/" + fileName)
	if err != nil {
		log.Println(err)
	} else {
		log.Printf("Previous report for image: %s deleted successfully \n", image)
	}
	return "reports/" + fileName
}

func writeHTMLOne(image, tag, registry, inc string, writer *bufio.Writer, w *os.File) {
	f, err := os.Open(inc)
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "&&TITLE&&") {
			title := strings.Replace(scanner.Text(), "&&TITLE&&", registry+"/"+image+":"+tag+" Risk Report", 1)
			writer.WriteString(title)
		} else if strings.Contains(scanner.Text(), "&&IMAGE&&") {
			img := strings.Replace(scanner.Text(), "&&IMAGE&&", registry+"/"+image+":"+tag, 1)
			writer.WriteString(img)
		} else {
			writer.WriteString(scanner.Text())
		}
	}
	writer.Flush()
}

func writeHTMLRisk(image, tag string, ir ImageRisk, writer *bufio.Writer, w *os.File) {
	if ir.Disallowed {
		str := fmt.Sprintf("<tr id=\"non-compliant\"><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%t</td><td>%t</td><td>%s</td></tr>", ir.VulnsFound, ir.HighVulns, ir.MedVulns, ir.LowVulns, ir.NegVulns, ir.Malware, ir.SensitiveData, ir.Whitelisted, ir.Blacklisted, ir.ScanDate.String())
		writer.WriteString(str)
	} else {
		str := fmt.Sprintf("<tr id=\"compliant\"><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%t</td><td>%t</td><td>%s</td></tr>", ir.VulnsFound, ir.HighVulns, ir.MedVulns, ir.LowVulns, ir.NegVulns, ir.Malware, ir.SensitiveData, ir.Whitelisted, ir.Blacklisted, ir.ScanDate.String())
		writer.WriteString(str)
	}

	writer.Flush()
}

func writeHTMLVulnerability(vuln ImageVulnerabilities, writer *bufio.Writer, w *os.File) {

	for _, v := range vuln.Result {
		if v.Resource.Type == "package" {
			str := fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%f</td><td>%s</td><td>%s</td><td>%s</td></tr>", v.Name, v.Resource.Type+"-"+v.Resource.Name, v.FixVersion, v.AquaScore, v.AquaSeverity, v.PublishDate, v.ModificationDate)
			writer.WriteString(str)
		} else {
			str := fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%f</td><td>%s</td><td>%s</td><td>%s</td></tr>", v.Name, v.Resource.Type+"-"+v.Resource.Path, v.FixVersion, v.AquaScore, v.AquaSeverity, v.PublishDate, v.ModificationDate)
			writer.WriteString(str)
		}
	}
	writer.Flush()
}

func writeHTMLSensitive(sens Sensitive, writer *bufio.Writer, w *os.File) {
	for _, v := range sens.Result {
		str := fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", v.Type, v.Filename, v.Path, v.Hash)
		writer.WriteString(str)
	}
	writer.Flush()
}

func writeHTMLMalware(malw Malware, writer *bufio.Writer, w *os.File) {
	for _, v := range malw.Result {
		str := fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", v.Malware, v.Hash, v.Path, v.Paths)
		writer.WriteString(str)
	}
	writer.Flush()
}
