package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// VulnerabilityResource is used in the ResourceReport below
type VulnerabilityResource struct {
	Name       string
	Severity   string
	Score      float64
	URL        string
	FixVersion string
}

// ResourceReport is used to create the Vulnerabilities Tab in HTML Report
type ResourceReport struct {
	Type          string
	Format        string
	Path          string
	Name          string
	Version       string
	Arch          string
	Vulnerability []VulnerabilityResource
}

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

func getSvgCompliant(ir ImageRisk) string {
	str := fmt.Sprintf(`<div class="image-status box">	
		<svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" class="icon-check text-success">
			<title>check-circle</title>
			<path d="M31.644 2.209l-15.989 18.656c-0.241 0.281-0.59 0.448-0.961 0.463-0.017 0.001-0.033 0.001-0.051 0.001-0.352 0-0.692-0.141-0.942-0.391l-6.662-6.662c-0.521-0.519-0.521-1.364 0-1.885 0.521-0.519 1.364-0.519 1.883 0l5.646 5.645 15.054-17.562c0.479-0.558 1.321-0.624 1.878-0.145 0.56 0.479 0.624 1.32 0.145 1.879zM19.428 6.207c-1.341-0.601-2.818-0.869-4.785-0.869-6.613 0-11.992 5.381-11.992 11.992 0 6.614 5.38 11.994 11.992 11.994s11.992-5.38 11.992-11.994c0-1.229-0.181-2.298-0.605-3.577-0.233-0.697 0.146-1.452 0.843-1.685 0.696-0.23 1.452 0.147 1.684 0.845 0.514 1.545 0.743 2.907 0.743 4.417 0 8.082-6.575 14.659-14.657 14.659s-14.657-6.576-14.657-14.659c0-8.082 6.575-14.657 14.657-14.657 2.329 0 4.195 0.349 5.874 1.1 0.672 0.3 0.973 1.088 0.673 1.76-0.301 0.672-1.087 0.973-1.762 0.673z"></path>
		</svg>
		<h2 class="text-success">Image Is Allowed</h2>

		<h5>Image scanned on %s</h5>
		</div>`, ir.ScanDate.String())
	return str
}

func getSvgNonCompliant(ir ImageRisk) string {
	str := fmt.Sprintf(`<div class="image-status box">
		<svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" class="icon-warning-triangle text-alert">
			<path d="M30.587 30.447c-0.009 0-0.017 0-0.027 0h-29.259c-0.469 0-0.905-0.248-1.144-0.652-0.24-0.403-0.248-0.904-0.021-1.315l14.629-26.533c0.467-0.847 1.864-0.847 2.331 0l14.516 26.328c0.191 0.229 0.305 0.524 0.305 0.845 0 0.732-0.596 1.327-1.331 1.327zM15.931 5.34l-12.38 22.453h24.76l-12.38-22.453zM15.931 11.873c0.735 0 1.331 0.593 1.331 1.327v6.633c0 0.732-0.596 1.327-1.331 1.327s-1.329-0.595-1.329-1.327v-6.633c0-0.733 0.595-1.327 1.329-1.327zM16.879 22.871c0.239 0.252 0.385 0.597 0.385 0.943s-0.147 0.689-0.399 0.941c-0.24 0.239-0.585 0.385-0.931 0.385-0.36 0-0.692-0.147-0.944-0.385-0.253-0.252-0.387-0.596-0.387-0.941s0.133-0.691 0.387-0.943c0.491-0.491 1.396-0.491 1.888 0z"></path>
		</svg>					
		<h2 class="text-alert">Image Is Non-Compliant</h2>
		<h5>Image scanned on %s</h5>
		</div>`, ir.ScanDate.String())
	return str
}

func writeHTMLRiskNonCompliantv2(ir ImageRisk, writer *bufio.Writer, w *os.File) {
	str := fmt.Sprintf(`<li><svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" class="icon-warning-triangle text-alert">
		<path d="M30.587 30.447c-0.009 0-0.017 0-0.027 0h-29.259c-0.469 0-0.905-0.248-1.144-0.652-0.24-0.403-0.248-0.904-0.021-1.315l14.629-26.533c0.467-0.847 1.864-0.847 2.331 0l14.516 26.328c0.191 0.229 0.305 0.524 0.305 0.845 0 0.732-0.596 1.327-1.331 1.327zM15.931 5.34l-12.38 22.453h24.76l-12.38-22.453zM15.931 11.873c0.735 0 1.331 0.593 1.331 1.327v6.633c0 0.732-0.596 1.327-1.331 1.327s-1.329-0.595-1.329-1.327v-6.633c0-0.733 0.595-1.327 1.329-1.327zM16.879 22.871c0.239 0.252 0.385 0.597 0.385 0.943s-0.147 0.689-0.399 0.941c-0.24 0.239-0.585 0.385-0.931 0.385-0.36 0-0.692-0.147-0.944-0.385-0.253-0.252-0.387-0.596-0.387-0.941s0.133-0.691 0.387-0.943c0.491-0.491 1.396-0.491 1.888 0z"></path>
		</svg>`)
	writer.WriteString(str)

}

func writeHTMLRiskNonCompliant(ir ImageRisk, writer *bufio.Writer, w *os.File) {
	for _, fail := range ir.AssuranceResults.ChecksPerformed {
		if (fail.Failed) && (fail.Control == "cve_blacklist") {
			str := fmt.Sprintf(`<li><svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" class="icon-warning-triangle text-alert">
				<path d="M30.587 30.447c-0.009 0-0.017 0-0.027 0h-29.259c-0.469 0-0.905-0.248-1.144-0.652-0.24-0.403-0.248-0.904-0.021-1.315l14.629-26.533c0.467-0.847 1.864-0.847 2.331 0l14.516 26.328c0.191 0.229 0.305 0.524 0.305 0.845 0 0.732-0.596 1.327-1.331 1.327zM15.931 5.34l-12.38 22.453h24.76l-12.38-22.453zM15.931 11.873c0.735 0 1.331 0.593 1.331 1.327v6.633c0 0.732-0.596 1.327-1.331 1.327s-1.329-0.595-1.329-1.327v-6.633c0-0.733 0.595-1.327 1.329-1.327zM16.879 22.871c0.239 0.252 0.385 0.597 0.385 0.943s-0.147 0.689-0.399 0.941c-0.24 0.239-0.585 0.385-0.931 0.385-0.36 0-0.692-0.147-0.944-0.385-0.253-0.252-0.387-0.596-0.387-0.941s0.133-0.691 0.387-0.943c0.491-0.491 1.396-0.491 1.888 0z"></path>
				</svg>`)
			writer.WriteString(str)
			str = fmt.Sprintf("Image contains blacklisted vulnerabilities: ")
			for i, v := range fail.BlacklistedCvesFound {
				if i == 0 {
					str = str + fmt.Sprintf("<strong>%s</strong>", v)
				} else {
					str = str + fmt.Sprintf(", <strong>%s</strong>", v)
				}
			}
			writer.WriteString(str + "</li>")
		} else if (fail.Failed) && (fail.Control == "sensitive_data") {
			str := fmt.Sprintf(`<li><svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" class="icon-warning-triangle text-alert">
				<path d="M30.587 30.447c-0.009 0-0.017 0-0.027 0h-29.259c-0.469 0-0.905-0.248-1.144-0.652-0.24-0.403-0.248-0.904-0.021-1.315l14.629-26.533c0.467-0.847 1.864-0.847 2.331 0l14.516 26.328c0.191 0.229 0.305 0.524 0.305 0.845 0 0.732-0.596 1.327-1.331 1.327zM15.931 5.34l-12.38 22.453h24.76l-12.38-22.453zM15.931 11.873c0.735 0 1.331 0.593 1.331 1.327v6.633c0 0.732-0.596 1.327-1.331 1.327s-1.329-0.595-1.329-1.327v-6.633c0-0.733 0.595-1.327 1.329-1.327zM16.879 22.871c0.239 0.252 0.385 0.597 0.385 0.943s-0.147 0.689-0.399 0.941c-0.24 0.239-0.585 0.385-0.931 0.385-0.36 0-0.692-0.147-0.944-0.385-0.253-0.252-0.387-0.596-0.387-0.941s0.133-0.691 0.387-0.943c0.491-0.491 1.396-0.491 1.888 0z"></path>
				</svg>`)
			writer.WriteString(str)
			writer.WriteString("Remove Sensitive Data from Image</li>")
		} else if (fail.Failed) && (fail.Control == "malware") {
			str := fmt.Sprintf(`<li><svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" class="icon-warning-triangle text-alert">
				<path d="M30.587 30.447c-0.009 0-0.017 0-0.027 0h-29.259c-0.469 0-0.905-0.248-1.144-0.652-0.24-0.403-0.248-0.904-0.021-1.315l14.629-26.533c0.467-0.847 1.864-0.847 2.331 0l14.516 26.328c0.191 0.229 0.305 0.524 0.305 0.845 0 0.732-0.596 1.327-1.331 1.327zM15.931 5.34l-12.38 22.453h24.76l-12.38-22.453zM15.931 11.873c0.735 0 1.331 0.593 1.331 1.327v6.633c0 0.732-0.596 1.327-1.331 1.327s-1.329-0.595-1.329-1.327v-6.633c0-0.733 0.595-1.327 1.329-1.327zM16.879 22.871c0.239 0.252 0.385 0.597 0.385 0.943s-0.147 0.689-0.399 0.941c-0.24 0.239-0.585 0.385-0.931 0.385-0.36 0-0.692-0.147-0.944-0.385-0.253-0.252-0.387-0.596-0.387-0.941s0.133-0.691 0.387-0.943c0.491-0.491 1.396-0.491 1.888 0z"></path>
				</svg>`)
			writer.WriteString(str)
			writer.WriteString("Remove Malware from Image</li>")
		} else if (fail.Failed) && (fail.Control == "max_severity") {
			str := fmt.Sprintf(`<li><svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" class="icon-warning-triangle text-alert">
				<path d="M30.587 30.447c-0.009 0-0.017 0-0.027 0h-29.259c-0.469 0-0.905-0.248-1.144-0.652-0.24-0.403-0.248-0.904-0.021-1.315l14.629-26.533c0.467-0.847 1.864-0.847 2.331 0l14.516 26.328c0.191 0.229 0.305 0.524 0.305 0.845 0 0.732-0.596 1.327-1.331 1.327zM15.931 5.34l-12.38 22.453h24.76l-12.38-22.453zM15.931 11.873c0.735 0 1.331 0.593 1.331 1.327v6.633c0 0.732-0.596 1.327-1.331 1.327s-1.329-0.595-1.329-1.327v-6.633c0-0.733 0.595-1.327 1.329-1.327zM16.879 22.871c0.239 0.252 0.385 0.597 0.385 0.943s-0.147 0.689-0.399 0.941c-0.24 0.239-0.585 0.385-0.931 0.385-0.36 0-0.692-0.147-0.944-0.385-0.253-0.252-0.387-0.596-0.387-0.941s0.133-0.691 0.387-0.943c0.491-0.491 1.396-0.491 1.888 0z"></path>
				</svg>`)
			writer.WriteString(str)
			writer.WriteString(fmt.Sprintf("Image severity <strong>%s</strong> exceeds the allowed max severity <strong>%s</strong></li>", fail.MaxSeverityFound, fail.MaxSeverityAllowed))
		} else if (fail.Failed) && (fail.Control == "root_user") {
			str := fmt.Sprintf(`<li><svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" class="icon-warning-triangle text-alert">
				<path d="M30.587 30.447c-0.009 0-0.017 0-0.027 0h-29.259c-0.469 0-0.905-0.248-1.144-0.652-0.24-0.403-0.248-0.904-0.021-1.315l14.629-26.533c0.467-0.847 1.864-0.847 2.331 0l14.516 26.328c0.191 0.229 0.305 0.524 0.305 0.845 0 0.732-0.596 1.327-1.331 1.327zM15.931 5.34l-12.38 22.453h24.76l-12.38-22.453zM15.931 11.873c0.735 0 1.331 0.593 1.331 1.327v6.633c0 0.732-0.596 1.327-1.331 1.327s-1.329-0.595-1.329-1.327v-6.633c0-0.733 0.595-1.327 1.329-1.327zM16.879 22.871c0.239 0.252 0.385 0.597 0.385 0.943s-0.147 0.689-0.399 0.941c-0.24 0.239-0.585 0.385-0.931 0.385-0.36 0-0.692-0.147-0.944-0.385-0.253-0.252-0.387-0.596-0.387-0.941s0.133-0.691 0.387-0.943c0.491-0.491 1.396-0.491 1.888 0z"></path>
				</svg>`)
			writer.WriteString(str)
			writer.WriteString("Create a non-root user for the image</li>")
		} else if (fail.Failed) && (fail.Control == "custom_checks") {
			str := fmt.Sprintf(`<li><svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" class="icon-warning-triangle text-alert">
				<path d="M30.587 30.447c-0.009 0-0.017 0-0.027 0h-29.259c-0.469 0-0.905-0.248-1.144-0.652-0.24-0.403-0.248-0.904-0.021-1.315l14.629-26.533c0.467-0.847 1.864-0.847 2.331 0l14.516 26.328c0.191 0.229 0.305 0.524 0.305 0.845 0 0.732-0.596 1.327-1.331 1.327zM15.931 5.34l-12.38 22.453h24.76l-12.38-22.453zM15.931 11.873c0.735 0 1.331 0.593 1.331 1.327v6.633c0 0.732-0.596 1.327-1.331 1.327s-1.329-0.595-1.329-1.327v-6.633c0-0.733 0.595-1.327 1.329-1.327zM16.879 22.871c0.239 0.252 0.385 0.597 0.385 0.943s-0.147 0.689-0.399 0.941c-0.24 0.239-0.585 0.385-0.931 0.385-0.36 0-0.692-0.147-0.944-0.385-0.253-0.252-0.387-0.596-0.387-0.941s0.133-0.691 0.387-0.943c0.491-0.491 1.396-0.491 1.888 0z"></path>
				</svg>`)
			writer.WriteString(str)
			str = fmt.Sprintf("Some custom checks failed: ")
			for i, v := range fail.CustomChecksFailed {
				if i == 0 {
					str = str + fmt.Sprintf("<strong>%s</strong>", v.ScriptName)
				} else {
					str = str + fmt.Sprintf(", <strong>%s</strong>", v.ScriptName)
				}
			}
			writer.WriteString(str + "</li>")
		}
	}
	writer.Flush()
}

func writeHTMLRiskv2(inc string, ir ImageRisk, writer *bufio.Writer, w *os.File) {
	f, err := os.Open(inc)
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "&&IMAGE&&:&&TAG&&") {
			tag := strings.Replace(scanner.Text(), "&&IMAGE&&:&&TAG&&", ir.Repository+":"+ir.Tag, 1)
			writer.WriteString(tag)
		} else if strings.Contains(scanner.Text(), "&&IMAGE&&") {
			img := strings.Replace(scanner.Text(), "&&IMAGE&&", ir.Repository, 1)
			writer.WriteString(img)
		} else if strings.Contains(scanner.Text(), "&&REGISTRY&&") {
			img := strings.Replace(scanner.Text(), "&&REGISTRY&&", ir.Registry, 1)
			writer.WriteString(img)
		} else if strings.Contains(scanner.Text(), "&&DISALLOWED&&") {
			if ir.Disallowed == true {
				img := strings.Replace(scanner.Text(), "&&DISALLOWED&&", "Non-Compliant", 1)
				writer.WriteString(img)
			} else {
				img := strings.Replace(scanner.Text(), "&&DISALLOWED&&", "Compliant", 1)
				writer.WriteString(img)
			}
		} else if strings.Contains(scanner.Text(), "&&SCANDATE&&") {
			img := strings.Replace(scanner.Text(), "&&SCANDATE&&", ir.ScanDate.String(), 1)
			writer.WriteString(img)
		} else if strings.Contains(scanner.Text(), "&&CRITICAL&&") {
			img := strings.Replace(scanner.Text(), "&&CRITICAL&&", strconv.Itoa(ir.VulnsFound), 1)
			writer.WriteString(img)
		} else if strings.Contains(scanner.Text(), "&&HIGH&&") {
			img := strings.Replace(scanner.Text(), "&&HIGH&&", strconv.Itoa(ir.HighVulns), 1)
			writer.WriteString(img)
		} else if strings.Contains(scanner.Text(), "&&MEDIUM&&") {
			img := strings.Replace(scanner.Text(), "&&MEDIUM&&", strconv.Itoa(ir.MedVulns), 1)
			writer.WriteString(img)
		} else if strings.Contains(scanner.Text(), "&&LOW&&") {
			img := strings.Replace(scanner.Text(), "&&LOW&&", strconv.Itoa(ir.LowVulns), 1)
			writer.WriteString(img)
		} else if strings.Contains(scanner.Text(), "&&NEGLIGIBLE&&") {
			img := strings.Replace(scanner.Text(), "&&NEGLIGIBLE&&", strconv.Itoa(ir.NegVulns), 1)
			writer.WriteString(img)
		} else {
			writer.WriteString(scanner.Text())
		}
	}
	writer.Flush()
}

func writeHTMLSensitive(sens Sensitive, writer *bufio.Writer, w *os.File) {
	if sens.Count == 0 {
		writer.WriteString(`<tr><td colspan="2"><em>No sensitive data found during scan</em></td></tr>`)
	} else {
		for _, s := range sens.Result {
			writer.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</tr>`, s.Path, s.Type))
		}
	}
	writer.Flush()
}

func writeHTMLMalware(malw Malware, writer *bufio.Writer, w *os.File) {
	if malw.Count == 0 {
		writer.WriteString(`<tr><td colspan="2"><em>No malware detected during scan</em></td></tr>`)
	} else {
		for _, m := range malw.Result {
			writer.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</tr>`, m.Path, m.Malware))
		}
	}
	writer.Flush()
}

func writeHTMLVulnerability(vulns ImageVulnerabilities, writer *bufio.Writer, w *os.File) {
	str := fmt.Sprintf(`<table id="cves" class="table-data vulns"><thead><tr>
							<th scope="col">Name</th>
							<th scope="col">Resource</th>
							<th scope="col">Severity</th>
							<th scope="col">Score</th>
							<th scope="col">Fix Version</th></tr>
							</thead><tbody>`)
	writer.WriteString(str)
	for _, vuln := range vulns.Result {
		str := fmt.Sprintf(`<tr><td><a href="%s" target="_blank">%s</a></td>
							   <td>%s</td><td><span class="severity %s">%s</span></td>
							   <td><span>%f</span></td>
							   <td>%s</td></tr>`, vuln.VendorURL, vuln.Name, vuln.Resource, strings.ToLower(vuln.AquaSeverity), strings.ToLower(vuln.AquaSeverity), vuln.AquaScore, vuln.FixVersion)
		writer.WriteString(str)
	}
	writer.Flush()
}

func writeHTMLResource(vulns map[string]ResourceReport, writer *bufio.Writer, w *os.File) {
	i := 1
	for _, resource := range vulns {
		// Initial Resource Table Header + Resource Name
		str := fmt.Sprintf(`<div class="table-data flex flex-wrap"><input type="checkbox" class="expand" id="expand%d-tab2">
				<label for="expand%d-tab2" class="data-item flex1">
				<span class="chevron-right">&#9658;</span>
				<span class="chevron-down">&#9660;</span>`, i, i)
		writer.WriteString(str)
		// Resource Row Values
		if resource.Type == "package" {
			str = fmt.Sprintf(`%s </label><span class="flex1 data-item">%s</span>`, resource.Name, resource.Type)
			str = str + fmt.Sprintf(`<span class="flex1 data-item">%s</span>`, resource.Version)
			str = str + fmt.Sprintf(`<span class="flex1 data-item">%s</span>`, resource.Format)
			str = str + fmt.Sprintf(`<span class="flex1 data-item">%s</span>`, resource.Arch)
			writer.WriteString(str)
		} else {
			str = fmt.Sprintf(`%s </label><span class="flex1 data-item">%s</span>`, resource.Path, resource.Type)
			str = str + fmt.Sprintf(`<span class="flex1 data-item">%s</span>`, resource.Version)
			str = str + fmt.Sprintf(`<span class="flex1 data-item">%s</span>`, resource.Format)
			str = str + fmt.Sprintf(`<span class="flex1 data-item">%s</span>`, resource.Arch)
			writer.WriteString(str)
		}

		// VUlnerability Table inside Resource drop down
		str = `<div class="more-info px10">
				<table>
				<thead>
				  <tr>
					<th scope="col">Name</th>
					<th scope="col">Severity</th>
					<th scope="col">Score</th>
					<th scope="col">Fix Version</th>
				  </tr>
				</thead>
				<tbody>`
		writer.WriteString(str)
		// Loop through Vulnerabilities and Write table data
		for _, vuln := range resource.Vulnerability {
			str := fmt.Sprintf(`<tr><td><a href="%s" target="_blank">%s</a></td>`, vuln.URL, vuln.Name)
			str = str + fmt.Sprintf(`<td><span class="severity %s">%s</span></td>`, strings.ToLower(vuln.Severity), strings.ToLower(vuln.Severity))
			str = str + fmt.Sprintf(`<td><span>%f</span></td><td>%s</td></tr>`, vuln.Score, vuln.FixVersion)
			writer.WriteString(str)
		}
		writer.WriteString("</tbody></table></div></div>")
		i++
	}
	writer.WriteString("</div>")
	writer.Flush()
}

func getResourceFromVuln(vulns ImageVulnerabilities) map[string]ResourceReport {
	var m map[string]ResourceReport
	m = make(map[string]ResourceReport)
	for _, result := range vulns.Result {
		vuln := VulnerabilityResource{result.Name, result.AquaSeverity, result.AquaScore, result.VendorURL, result.FixVersion}
		_, ok := m[result.Resource.Name]
		if ok {
			resource := m[result.Resource.Name]
			v := resource.Vulnerability
			v = append(v, vuln)
			newResource := ResourceReport{result.Resource.Type, result.Resource.Format, result.Resource.Path, result.Resource.Name, result.Resource.Version, result.Resource.Arch, v}
			m[result.Resource.Name] = newResource
		} else {
			resource := ResourceReport{result.Resource.Type, result.Resource.Format, result.Resource.Path, result.Resource.Name, result.Resource.Version, result.Resource.Arch, []VulnerabilityResource{vuln}}
			m[result.Resource.Name] = resource
		}
	}
	return m
}
