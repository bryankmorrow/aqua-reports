package main

import (
	"fmt"
	"log"
	"strconv"

	"github.com/360EntSecGroup-Skylar/excelize"
)

func createSpreadsheet(image string) *excelize.File {
	f := excelize.NewFile()

	risk := f.NewSheet("Risk")
	f.NewSheet("Vulnerabilities")
	f.NewSheet("Malware")
	f.NewSheet("Sensitive")
	f.DeleteSheet("Sheet1")

	f.SetActiveSheet(risk)

	headers, err := f.NewStyle(`{"alignment":{"horizontal":"center"}}`)
	if err != nil {
		log.Fatal(err)
	}

	f.SetCellStyle("Risk", "A1", "A1", headers)
	f.SetCellStyle("Risk", "B1", "B1", headers)
	f.SetCellStyle("Risk", "C1", "C1", headers)
	f.SetCellStyle("Risk", "D1", "D1", headers)
	f.SetCellStyle("Risk", "E1", "E1", headers)
	f.SetCellStyle("Risk", "F1", "F1", headers)
	f.SetCellStyle("Risk", "G1", "G1", headers)
	f.SetCellStyle("Risk", "H1", "H1", headers)
	f.SetCellStyle("Risk", "I1", "I1", headers)
	f.SetCellStyle("Risk", "J1", "J1", headers)
	f.SetCellStyle("Risk", "K1", "K1", headers)
	f.SetCellStyle("Risk", "L1", "L1", headers)
	f.SetCellStyle("Risk", "M1", "M1", headers)
	f.SetCellStyle("Risk", "N1", "N1", headers)

	f.SetCellStyle("Vulnerabilities", "A1", "A1", headers)
	f.SetCellStyle("Vulnerabilities", "B1", "B1", headers)
	f.SetCellStyle("Vulnerabilities", "C1", "C1", headers)
	f.SetCellStyle("Vulnerabilities", "D1", "D1", headers)
	f.SetCellStyle("Vulnerabilities", "E1", "E1", headers)
	f.SetCellStyle("Vulnerabilities", "F1", "F1", headers)
	f.SetCellStyle("Vulnerabilities", "G1", "G1", headers)
	f.SetCellStyle("Vulnerabilities", "H1", "H1", headers)
	f.SetCellStyle("Vulnerabilities", "I1", "I1", headers)
	f.SetCellStyle("Vulnerabilities", "J1", "J1", headers)
	f.SetCellStyle("Vulnerabilities", "K1", "K1", headers)
	f.SetCellStyle("Vulnerabilities", "L1", "L1", headers)
	f.SetCellStyle("Vulnerabilities", "M1", "M1", headers)
	f.SetCellStyle("Vulnerabilities", "N1", "N1", headers)
	f.SetCellStyle("Vulnerabilities", "O1", "O1", headers)
	f.SetCellStyle("Vulnerabilities", "P1", "P1", headers)
	f.SetCellStyle("Vulnerabilities", "Q1", "Q1", headers)

	f.SetCellStyle("Malware", "A1", "A1", headers)
	f.SetCellStyle("Malware", "B1", "B1", headers)
	f.SetCellStyle("Malware", "C1", "C1", headers)
	f.SetCellStyle("Malware", "D1", "D1", headers)

	f.SetCellStyle("Risk", "A1", "A1", headers)
	f.SetCellStyle("Risk", "B1", "B1", headers)
	f.SetCellStyle("Risk", "C1", "C1", headers)
	f.SetCellStyle("Risk", "D1", "D1", headers)

	// Set Risk Columns
	f.SetCellValue("Risk", "A1", "Image")
	f.SetCellValue("Risk", "B1", "Tag")
	f.SetCellValue("Risk", "C1", "Registry")
	f.SetCellValue("Risk", "D1", "Non-Compliant")
	f.SetCellValue("Risk", "E1", "Scan Date")
	f.SetCellValue("Risk", "F1", "Total Vulns")
	f.SetCellValue("Risk", "G1", "High Vulns")
	f.SetCellValue("Risk", "H1", "Medium Vulns")
	f.SetCellValue("Risk", "I1", "Low Vulns")
	f.SetCellValue("Risk", "J1", "Negligible Vulns")
	f.SetCellValue("Risk", "K1", "Malware Count")
	f.SetCellValue("Risk", "L1", "Sensitive Data Count")
	f.SetCellValue("Risk", "M1", "Whitelisted")
	f.SetCellValue("Risk", "N1", "Blacklisted")

	// Set Vulnerability Columns
	f.SetCellValue("Vulnerabilities", "A1", "Vulnerability")
	f.SetCellValue("Vulnerabilities", "B1", "Resource")
	f.SetCellValue("Vulnerabilities", "C1", "Description")
	f.SetCellValue("Vulnerabilities", "D1", "Fix Version")
	f.SetCellValue("Vulnerabilities", "E1", "Solution")
	f.SetCellValue("Vulnerabilities", "F1", "Aqua Score")
	f.SetCellValue("Vulnerabilities", "G1", "Aqua Severity")
	f.SetCellValue("Vulnerabilities", "H1", "NVD Score")
	f.SetCellValue("Vulnerabilities", "I1", "NVD Severity")
	f.SetCellValue("Vulnerabilities", "J1", "NVD Vectors")
	f.SetCellValue("Vulnerabilities", "K1", "NVD Reference")
	f.SetCellValue("Vulnerabilities", "L1", "Vendor Score")
	f.SetCellValue("Vulnerabilities", "M1", "Vendor Severity")
	f.SetCellValue("Vulnerabilities", "N1", "Vendor Vectors")
	f.SetCellValue("Vulnerabilities", "O1", "Vendor Reference")
	f.SetCellValue("Vulnerabilities", "P1", "Publish Date")
	f.SetCellValue("Vulnerabilities", "Q1", "Modification Date")

	// Set Malware Columns
	f.SetCellValue("Malware", "A1", "Malware")
	f.SetCellValue("Malware", "B1", "Hash")
	f.SetCellValue("Malware", "C1", "Path")
	f.SetCellValue("Malware", "D1", "Paths")

	// Set Sensitive Columns
	f.SetCellValue("Sensitive", "A1", "Sensitive Data")
	f.SetCellValue("Sensitive", "B1", "Filename")
	f.SetCellValue("Sensitive", "C1", "Path")
	f.SetCellValue("Sensitive", "D1", "Hash")

	return f
}

func saveFile(f *excelize.File, image string) string {
	// Save xlsx file by the given path.
	var response string
	err := f.SaveAs("reports/" + image + ".xlsx")
	if err != nil {
		fmt.Println(err)
		response = "failed to save file"
	} else {
		response = "successfully saved file"
	}
	return response
}

func writeRisk(f *excelize.File, ir ImageRisk) {
	f.SetCellStr("Risk", "A2", ir.Repository)
	f.SetCellValue("Risk", "B2", ir.Tag)
	f.SetCellStr("Risk", "C2", ir.Registry)
	f.SetCellBool("Risk", "D2", ir.Disallowed)
	f.SetCellValue("Risk", "E2", ir.ScanDate)
	f.SetCellInt("Risk", "F2", ir.VulnsFound)
	f.SetCellInt("Risk", "G2", ir.HighVulns)
	f.SetCellInt("Risk", "H2", ir.MedVulns)
	f.SetCellInt("Risk", "I2", ir.LowVulns)
	f.SetCellInt("Risk", "J2", ir.NegVulns)
	f.SetCellInt("Risk", "K2", ir.Malware)
	f.SetCellInt("Risk", "L2", ir.SensitiveData)
	f.SetCellBool("Risk", "M2", ir.Whitelisted)
	f.SetCellBool("Risk", "N2", ir.Blacklisted)
}

func writeVulnerabilities(f *excelize.File, vuln ImageVulnerabilities) {
	i := 2
	for _, v := range vuln.Result {
		if v.AquaScoringSystem == "CVSS V2" {
			f.SetCellValue("Vulnerabilities", "H"+strconv.Itoa(i), v.NvdCvss2Score)
			f.SetCellStr("Vulnerabilities", "I"+strconv.Itoa(i), v.NvdSeverity)
			f.SetCellStr("Vulnerabilities", "J"+strconv.Itoa(i), v.NvdCvss2Vectors)
			f.SetCellStr("Vulnerabilities", "K"+strconv.Itoa(i), v.NvdURL)
			f.SetCellValue("Vulnerabilities", "L"+strconv.Itoa(i), v.VendorCvss2Score)
			f.SetCellStr("Vulnerabilities", "M"+strconv.Itoa(i), v.VendorSeverity)
			f.SetCellStr("Vulnerabilities", "N"+strconv.Itoa(i), v.VendorCvss2Vectors)
			f.SetCellStr("Vulnerabilities", "O"+strconv.Itoa(i), v.VendorURL)
		} else {
			f.SetCellValue("Vulnerabilities", "H"+strconv.Itoa(i), v.NvdCvss3Score)
			f.SetCellStr("Vulnerabilities", "I"+strconv.Itoa(i), v.NvdCvss3Severity)
			f.SetCellStr("Vulnerabilities", "J"+strconv.Itoa(i), v.NvdCvss3Vectors)
			f.SetCellStr("Vulnerabilities", "K"+strconv.Itoa(i), v.NvdURL)
			f.SetCellValue("Vulnerabilities", "L"+strconv.Itoa(i), v.VendorCvss3Score)
			f.SetCellStr("Vulnerabilities", "M"+strconv.Itoa(i), v.VendorCvss3Severity)
			f.SetCellStr("Vulnerabilities", "N"+strconv.Itoa(i), v.VendorCvss3Vectors)
			f.SetCellStr("Vulnerabilities", "O"+strconv.Itoa(i), v.VendorURL)
		}
		f.SetCellStr("Vulnerabilities", "A"+strconv.Itoa(i), v.Name)
		f.SetCellStr("Vulnerabilities", "B"+strconv.Itoa(i), v.Resource.Name)
		f.SetCellStr("Vulnerabilities", "C"+strconv.Itoa(i), v.Description)
		f.SetCellStr("Vulnerabilities", "D"+strconv.Itoa(i), v.FixVersion)
		f.SetCellStr("Vulnerabilities", "E"+strconv.Itoa(i), v.Solution)
		f.SetCellValue("Vulnerabilities", "F"+strconv.Itoa(i), v.AquaScore)
		f.SetCellStr("Vulnerabilities", "G"+strconv.Itoa(i), v.AquaSeverity)

		f.SetCellStr("Vulnerabilities", "P"+strconv.Itoa(i), v.PublishDate)
		f.SetCellStr("Vulnerabilities", "Q"+strconv.Itoa(i), v.ModificationDate)
		i++
	}
}

func writeSensitive(f *excelize.File, sens Sensitive) {
	i := 2
	for _, v := range sens.Result {
		f.SetCellStr("Sensitive", "A"+strconv.Itoa(i), v.Type)
		f.SetCellStr("Sensitive", "B"+strconv.Itoa(i), v.Filename)
		f.SetCellStr("Sensitive", "C"+strconv.Itoa(i), v.Path)
		f.SetCellStr("Sensitive", "D"+strconv.Itoa(i), v.Hash)
		i++
	}

}

func writeMalware(f *excelize.File, malw Malware) {
	i := 2
	for _, v := range malw.Result {
		f.SetCellStr("Malware", "A"+strconv.Itoa(i), v.Malware)
		f.SetCellStr("Malware", "B"+strconv.Itoa(i), v.Hash)
		f.SetCellStr("Malware", "C"+strconv.Itoa(i), v.Path)
		f.SetCellValue("Malware", "D"+strconv.Itoa(i), v.Paths)
		i++
	}
}
