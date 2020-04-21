package findings

import (
	"encoding/json"
	"github.com/BryanKMorrow/aqua-reports/pkg/types/images"
	"log"
	"net/http"
	"strconv"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
	"github.com/gorilla/mux"
)

type TagHistory []images.TagHistory

// TagHandler receives the http request, collects the tag history for all images and returns status to requester
func TagHandler(w http.ResponseWriter, r *http.Request) {
	var th TagHistory
	params := mux.Vars(r)
	queue := make(chan reports.Response)
	response := th.Get(params, queue)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (th *TagHistory) Get(params map[string]string, queue chan reports.Response) reports.Response {
	defer reports.Track(reports.RunningTime("tagHistory.Get"))
	reports.UnescapeURLQuery(params)
	cli := reports.GetClient(th)
	var thl []images.TagHistory
	// Get all repositories
	repos, _, _, _ := cli.GetRepositories(0, 1000, nil)
	// Loop through all repositories and get the tags
	for _, repo := range repos.Result {
		tag := images.TagHistory{
			Name:     repo.Name,
			Registry: repo.Registry,
		}
		params := make(map[string]string)
		params["registry"] = tag.Registry
		params["repository"] = tag.Name
		var rt []images.Tag
		img, _, _, _ := cli.GetAllImages(0, 1000, params, nil)
		for _, image := range img.Result {
			i, err := cli.GetImage(image.Registry, image.Repository, image.Tag)
			if err != nil {
				log.Println(err)
			} else {
				t := images.Tag{
					Name:       i.Tag,
					Created:    i.Metadata.Created,
					VulnsFound: i.VulnsFound,
					CritVulns:  i.CritVulns,
					HighVulns:  i.HighVulns,
					MedVulns:   i.MedVulns,
					LowVulns:   i.LowVulns,
					NegVulns:   i.NegVulns,
				}
				rt = append(rt, t)
			}
		}
		tag.Tags = rt
		thl = append(thl, tag)
	}
	var response = reports.Response{
		Message: "Tag History for all repos: " + strconv.Itoa(repos.Count),
		URL:     "",
		Status:  "Write Successful",
	}
	data, _ := json.Marshal(thl)
	log.Println(string(data))
	return response
}
