package router

import (
	"log"
	"net/http"

	"github.com/BryanKMorrow/aqua-reports/pkg/types/routes"
	ReportsHandler "github.com/BryanKMorrow/aqua-reports/src/controllers/v1/reports"
	StatusHandler "github.com/BryanKMorrow/aqua-reports/src/controllers/v1/status"
)

// Middleware - Handler to check for authentication
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/* token := r.Header.Get("X-App-Token")
		if len(token) < 1 {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		} */

		log.Println("Inside V1 Middleware")

		next.ServeHTTP(w, r)
	})
}

// GetRoutes - Returns the list of Sub Routes
func GetRoutes() (SubRoute map[string]routes.SubRoutePackage) {

	/* ROUTES */
	SubRoute = map[string]routes.SubRoutePackage{
		"/api/v1": {
			Routes: routes.Routes{
				routes.Route{Name: "Status", Method: "GET", Pattern: "/status", HandlerFunc: StatusHandler.Index},
				routes.Route{Name: "ReportsAllStreams", Method: "GET", Pattern: "/reports/streams/all", HandlerFunc: ReportsHandler.AllStream},
				routes.Route{Name: "ReportsAllParams", Method: "GET", Pattern: "/reports/all/{pagesize}/{page}", HandlerFunc: ReportsHandler.AllParams},
				routes.Route{Name: "ReportsAll", Method: "GET", Pattern: "/reports/all", HandlerFunc: ReportsHandler.All},
				routes.Route{Name: "Report", Method: "GET", Pattern: "/reports/{registry}/{image}/{tag}", HandlerFunc: ReportsHandler.One},
				routes.Route{Name: "Reports", Method: "POST", Pattern: "/reports/images", HandlerFunc: ReportsHandler.Post},
				routes.Route{Name: "ExecutiveOverview", Method: "GET", Pattern: "/reports/overview", HandlerFunc: ReportsHandler.Overview},
			},
			Middleware: Middleware,
		},
	}

	return
}
