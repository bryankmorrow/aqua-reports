package aqua

import (
	"encoding/json"
	"log"
	"strconv"

	"github.com/parnurzeal/gorequest"
)

// Return the remaining amount of repositories (images), the current page and the AllImages result
func (csp *CSP) repositoryResult(pagesize, page int) (int, int, AllImages) {
	var repos = AllImages{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	url := csp.url + "/api/v2/repositories?filter=&include_totals=true&order_by=name&pagesize=" + strconv.Itoa(pagesize) + "&page=" + strconv.Itoa(page)
	events, body, errs := request.Clone().Get(url).End()
	log.Printf("Querying /api/v2/repositories page number %v with a pagesize of %v", page, pagesize)
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &repos)
		if err != nil {
			log.Println(err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
	}
	remaining := repos.Count - (pagesize * page)
	return remaining, page, repos
}

func (csp *CSP) imageScanResult(registry, name string, pagesize int) ImageList {
	var list = ImageList{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	url := csp.url + "/api/v2/images?registry=" + registry + "&repository=" + name + "&page_size=" + strconv.Itoa(pagesize)
	events, body, errs := request.Clone().Get(url).End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &list)
		if err != nil {
			log.Println(err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
	}
	return list
}

func (csp *CSP) trendsResult(trend string) ResponseTrends {
	var response = ResponseTrends{}
	request := gorequest.New()
	request.Set("Authorization", "Bearer "+csp.token)
	url := csp.url + "/api/v1/dashboard/" + trend + "/trends"
	events, body, errs := request.Clone().Get(url).End()
	if errs != nil {
		log.Println(events.StatusCode)
	}
	if events.StatusCode == 200 {
		err := json.Unmarshal([]byte(body), &response)
		if err != nil {
			log.Println(err.Error())
			//json: Unmarshal(non-pointer main.Request)
		}
	}
	return response
}
