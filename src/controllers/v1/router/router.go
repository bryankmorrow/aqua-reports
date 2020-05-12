package router

import (
	"net/http"

	FindingHandler "github.com/BryanKMorrow/aqua-reports/pkg/api/reports/findings"
	ImageHandler "github.com/BryanKMorrow/aqua-reports/pkg/api/reports/images"
	RegistriesHandler "github.com/BryanKMorrow/aqua-reports/pkg/api/reports/registries"
	VulnerabilityHandler "github.com/BryanKMorrow/aqua-reports/pkg/api/reports/vulnerabilities"
	"github.com/BryanKMorrow/aqua-reports/pkg/types/routes"
	ReportsHandler "github.com/BryanKMorrow/aqua-reports/src/controllers/v1/reports"
	StatusHandler "github.com/BryanKMorrow/aqua-reports/src/controllers/v1/status"
)

// Middleware - Handler
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		"/api/v2": {
			Routes: routes.Routes{
				routes.Route{Name: "ImageReport", Method: "GET", Pattern: "/reports/scans/{image:.*}", HandlerFunc: ImageHandler.Handler},
				routes.Route{Name: "AllImagesReport", Method: "GET", Pattern: "/reports/scans", HandlerFunc: ImageHandler.AllHandler},
				routes.Route{Name: "Registries", Method: "GET", Pattern: "/reports/registries", HandlerFunc: RegistriesHandler.RegistriesHandler},
				routes.Route{Name: "Findings", Method: "GET", Pattern: "/reports/findings", HandlerFunc: FindingHandler.Handler},
				routes.Route{Name: "TagHistory", Method: "GET", Pattern: "/reports/repos/taghistory", HandlerFunc: FindingHandler.TagHandler},
				routes.Route{Name: "TopVulnerabilities", Method: "GET", Pattern: "/reports/vulnerabilities", HandlerFunc: VulnerabilityHandler.Handler},
			},
			Middleware: Middleware,
		},
	}

	return
}
