package images

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
	"github.com/gorilla/mux"

	"github.com/BryanKMorrow/aqua-sdk-go/types/images"
)

// Image contains the structure for a single image report
type Image struct {
	Risk            images.SingleResponse  `json:"risk"`
	Vulnerabilities images.Vulnerabilities `json:"vulnerabilities"`
	SensitiveData   images.Sensitive       `json:"sensitive_data"`
	Malware         images.Malware         `json:"malware"`
	Report          string                 `json:"template"`
	Response        reports.Response       `json:"response"`
}

// ImageHandler needs to handle the incoming request and execute the proper Image call
func ImageHandler(w http.ResponseWriter, r *http.Request) {
	var image Image
	// Get the registry, image and tag from the path parameters
	p := mux.Vars(r)
	str := p["image"]
	strings.TrimLeft(str, "/")
	strings.TrimRight(str, "/")
	split := strings.Split(str, "/")
	registry := split[0]
	tag := split[len(split)-1]
	var img string
	for i, s := range split {
		if i > 0 && i < len(split)-1 {
			if i == 1 {
				img = s
			} else {
				img = img + "/" + s
			}
		}
	}
	params := make(map[string]string)
	params["registry"] = registry
	params["image"] = img
	params["tag"] = tag
	reports.UnescapeURLQuery(params)
	response := image.Get(params, nil)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Get - single image risk report
// Param: http.ResponseWriter - writer to send back to requester
// Param: *http.Request - request
func (i *Image) Get(params map[string]string, queue chan reports.Response) reports.Response {
	defer reports.Track(reports.RunningTime("image.Get"))
	var err error
	//var remaining, total, next int

	// Get the request query parameters and unescape them
	reports.UnescapeURLQuery(params)
	// Get the client
	cli := reports.GetClient(i)
	// Get the Image Risk and verify the image exists
	i.Risk, err = cli.GetImage(params["registry"], params["image"], params["tag"])
	if err != nil {
		var response = reports.Response{
			Message: fmt.Sprintf("Scan Report for %s:%s in %s", params["registry"], params["image"], params["tag"]),
			URL:     "",
			Status:  "Image Not Found",
		}
		return response
	}
	// ignoring remaining, next, total for now
	i.Vulnerabilities, _, _, _ = cli.GetVulnerabilities(params["registry"], params["image"], params["tag"], 0, 1000, nil, nil)
	for k, v := range i.Vulnerabilities.Result {
		splitter := strings.Split(v.FixVersion, "\n")
		i.Vulnerabilities.Result[k].FixVersion = splitter[0]
	}
	i.SensitiveData = cli.GetSensitive(params["registry"], params["image"], params["tag"])
	i.Malware = cli.GetMalware(params["registry"], params["image"], params["tag"])
	// Create the Report File
	fileName := reports.CreateImageFile(params["registry"], params["image"], params["tag"])
	// Marshall the data
	risk, _ := json.Marshal(i.Risk)
	vuln, _ := json.Marshal(i.Vulnerabilities.Result)
	sens, _ := json.Marshal(i.SensitiveData.Result)
	malw, _ := json.Marshal(i.Malware.Result)
	// Save the template to the report file
	template := i.Template(string(risk), string(vuln), string(sens), string(malw))
	w, err := os.OpenFile(fileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	writer := bufio.NewWriter(w)
	writer.WriteString(template)
	writer.Flush()
	w.Close()
	var response = reports.Response{
		Message: fmt.Sprintf("Scan Report for %s:%s in %s", params["image"], params["tag"], params["registry"]),
		URL:     fileName,
		Status:  "Write Successful",
	}
	if queue != nil {
		queue <- response
	}
	return response
}

func (i *Image) Template(risk, vulnerabilities, sensitive, malware string) string {
	template := `<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="utf-8"/>
			<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@100;400;500;900&display=swap" rel="stylesheet">
			<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css">
			<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
		<style>
		body{font-family: 'Roboto','Open Sans', sans-serif; font-size: 14px;}
		hr{ color: #6a6a6a;}
		table{border: none;}
		td { text-align: center;height:25px;width:75px;color:#fff;white-space: pre-wrap;}
		tr{margin-bottom: 10px;}
		th {border: none; width:50px; text-align: center; white-space: pre-wrap;}
		h1{ font-weight: bold; margin-left: -10px;}
		h3{font-weight: 600; padding-top: 35px;}
		h5{font-weight: 600; padding-top: 15px; font-size: 16px;}
		[v-cloak] { display:none; }
		a:link, a:visited, a:hover, a:active {color: #000; text-decoration: none; }
		.truncate { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color:#000; text-align: left; padding-right: 10px; }
		.highlightme { background-color:#EFEFEF; }
		.badge-dark{background-color: #820040;}
		.badge-warning{background-color: #FF8E2A;}
		.badge-danger{background-color: #D90000;}
		.badge-primary{background-color:#357ABD;}
		.badge-secondary{background-color: #27A744}
		.hide2{visibility:hidden;}
		</style>
		</head>
		<body>
		
		<div class="container" id="app" v-cloak>
		<div class="row">
			<div class="col-md-6"><h3 style="margin-top: 50px;">Scan Report for {{risk.registry}}/{{risk.name}} on {{risk.scan_date}}</h3></div>
		  <!--  <div class="col-md-6 text-right"><img src="Logo.jpg" height="150px" width="300px" style="padding-bottom: 20px;"></div> -->
		</div>
		
		<div class="row" style="margin-top: -40px;">
		<div class="col-12">
		<h3>Risk</h3>
		<table style="margin-top: 15px; width: 100%">
		<thead>
		<th @click="sort('risk', 'name')" style="text-align: left;">Name</th>
		<th @click="sort('risk', 'registry')" style="text-align: left;">Registry</th>
		<th @click="sort('risk', 'disallowed')" style="text-align: left;"><a href="#">Compliant</a></th>
		<th @click="sort('risk', 'vulns_found')"><a href="#">Total Vulns</a></th>
		<th @click="sort('risk', 'crit_vulns')"><a href="#">Critical</a></th>
		<th @click="sort('risk', 'high_vulns')"><a href="#">High</a></th>
		<th @click="sort('risk', 'med_vulns')"><a href="#">Medium</a></th>
		<th @click="sort('risk', 'malware')"><a href="#">Malware</a></th>
		<th @click="sort('risk', 'sensitive_data')"><a href="#">Sensitive</a></th>
		
		</thead>
		<tr :key="index">
			<td style="color: #000; text-align: left;"><span>{{ risk.name }}</span></td>
			<td style="color: #000; text-align: left;"><span>{{ risk.registry }}</span></td>
			<td style="color: #000; text-align: left;"><span>{{ risk.disallowed }}</span></td>
			<td><span class="badge badge-primary">{{risk.vulns_found}}</span></td>
			<td><span class="badge badge-dark">{{risk.crit_vulns}}</span></td>
			<td><span class="badge badge-danger">{{risk.high_vulns}}</span></td>
			<td><span class="badge badge-warning">{{risk.med_vulns}}</span></td>
			<td><span class="badge badge-light">{{risk.malware}}</span></td>
			<td><span class="badge badge-light">{{risk.sensitive_data}}</span></td>
		</tr>
		</tbody>
		</table>
		</div>
		</div>
		
		<div class="row">
		<div class="col-12">
		
		<h3>Vulnerabilities</h3>
		<table style="margin-top: 15px;width: 100%">
		<thead>
			<th @click="sort('vulnerabilities', 'name', $event)" style="text-align: left;">Name</th>
			<th @click="sort('vulnerabilities','resource.name')" style="text-align: left;"><a href="#">Resource</a></th>
			<th @click="sort('vulnerabilities','severity')" style="text-align: left;"><a href="#">Severity</a></th>
			<th @click="sort('vulnerabilities','score')"><a href="#">Score</a></th>
			<th @click="sort('vulnerabilities','resource.version')"><a href="#">Version</a></th>
			<th @click="sort('vulnerabilities','fix_version')"><a href="#">Fix Version</a></th>
		</thead>
		<tr v-for="(vulnerability, index) in vulnerabilities" :key="index">
			<td style="color: #000; text-align: left;">{{vulnerability.name}}</td>
			<td style="color: #000; text-align: left;">{{vulnerability.resource.name}}</td>
			<td style="color: #000; text-align: left;">{{vulnerability.aqua_severity}}</td>
			<td style="color: #000;">{{vulnerability.aqua_score}}</td>
			<td style="color: #000;">{{vulnerability.resource.version}}</td>
			<td style="color: #000;">{{vulnerability.fix_version}}</td>
		</tr>
		</tbody>
		</table>
		
		</div><!-- end col-md-12 -->
		</div><!-- end row -->
		
		<div class="row">
			<div class="col-12">
		
				<h3>Malware</h3>
				<table style="margin-top: 15px;width: 100%">
					<thead>
					<th @click="sort('malware', 'malware', $event)" style="text-align: left;">Name</th>
					<th @click="sort('malware','path')" style="text-align: left;"><a href="#">Path</a></th>
					</thead>
					<tr v-for="(m, index) in malware" :key="index">
						<td style="color: #000; text-align: left;">{{m.malware}}</td>
						<td style="color: #000; text-align: left;">{{m.path}}</td>
					</tr>
					</tbody>
				</table>
		
			</div><!-- end col-md-12 -->
		</div><!-- end row -->
		
			<div class="row">
				<div class="col-12">
		
					<h3>Sensitive Data</h3>
					<table style="margin-top: 15px;width: 100%">
						<thead>
						<th @click="sort('sensitive', 'type', $event)" style="text-align: left;">Type</th>
						<th @click="sort('sensitive','filename')" style="text-align: left;"><a href="#">Filename</a></th>
						<th @click="sort('sensitive','path')" style="text-align: left;"><a href="#">Path</a></th>
						</thead>
						<tr v-for="(s, index) in sensitive" :key="index">
							<td style="color: #000; text-align: left;">{{s.type}}</td>
							<td style="color: #000; text-align: left;">{{s.filename}}</td>
							<td style="color: #000; text-align: left;">{{s.path}}</td>
						</tr>
						</tbody>
					</table>
		
				</div><!-- end col-md-12 -->
			</div><!-- end row -->
		
		</div><!-- end app -->
		
		<script src="https://cdn.jsdelivr.net/npm/vue/dist/vue.js"></script>
		<script src="https://kit.fontawesome.com/27e233ddae.js" crossorigin="anonymous"></script>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.24.0/moment-with-locales.min.js"></script>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/axios/0.19.0/axios.min.js"></script>
		
		<script>
		
			var poc = new Vue({
				el: '#app',
				data:{
					risk: {},
					vulnerabilities: [],
					sensitive: [],
					malware: [],
					activeIndex: 0,
					activeVulnerability:0,
					pageLoad: false,
				},
				 mounted: function (){
					 document.onreadystatechange = () => {
						if (document.readyState == "complete") {
							this.pageLoad = true;
						}
					 }
				},
				methods: {
					sort(collection, column, event){
					  if(column == 'name' || column == 'score' || column == 'severity'){
						  this[collection].sort((a, b) => a[column].localeCompare(b[column]))
					  }else{
						  this[collection].sort((a, b) => b[column] - a[column]);
					  }
					},
					parse_date(rawDate){
						const date = new Date(rawDate);
						return moment(date).format('MM-DD');
					},
				},
				computed:{},
				filters: {
				  spacing: function (value) {
					if(value < 10) {
						return " " + value;
					}else{
						return "" + value
					}
				  },
					url: function(prefix){
		
					  if(!prefix.search("https")){
						  return prefix.substring(8);
					  }else{
						  return prefix
					  }
					}
				}
			});
		</script>
		</body>
		</html>`
	r := strings.Replace(template, "risk: {}", "risk: "+risk, -1)
	re := strings.Replace(r, "vulnerabilities: []", "vulnerabilities: "+vulnerabilities, -1)
	res := strings.Replace(re, "sensitive: []", "sensitive: "+sensitive, -1)
	response := strings.Replace(res, "malware: []", "malware: "+malware, -1)
	return response
}
