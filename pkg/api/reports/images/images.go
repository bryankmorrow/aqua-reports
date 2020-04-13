package images

import (
	"encoding/json"
	"strconv"

	"log"
	"net/http"

	"github.com/BryanKMorrow/aqua-reports/pkg/api/reports"
	"github.com/gorilla/mux"
)

type Images []Image

// ImagesHandler needs to handle the incoming request and execute the proper Image call
func ImagesHandler(w http.ResponseWriter, r *http.Request) {
	var images Images
	params := mux.Vars(r)
	queue := make(chan reports.Response)
	response := images.Get(params, queue)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (il *Images) Get(params map[string]string, queue chan reports.Response) reports.Response {
	defer reports.Track(reports.RunningTime("images.Get"))
	var remaining, total, next int
	reports.UnescapeURLQuery(params)
	cli := reports.GetClient(il)
	all, remaining, next, total := cli.GetAllImages(0, 1000, nil, nil)
	log.Printf("Images: %d  Remaining: %d  Next Page: %d", total, remaining, next)
	for _, img := range all.Result {
		var image Image
		var p = make(map[string]string)
		p["registry"] = img.Registry
		p["image"] = img.Repository
		p["tag"] = img.Tag
		reports.UnescapeURLQuery(p)
		go image.Get(p, queue)
	}
	queueCount := 1
	for resp := range queue {
		log.Printf("Count: %d  Total: %d \n", queueCount, total)
		log.Println(resp)
		if queueCount == total {
			close(queue)
		}
		queueCount++
	}
	var response = reports.Response{
		Message: "Scan Report for all images: " + strconv.Itoa(total),
		URL:     "",
		Status:  "Write Successful",
	}
	return response
}
