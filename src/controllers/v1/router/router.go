package router

import (
	"log"
	"net/http"

	"github.com/BryanKMorrow/reports-v2/pkg/types/routes"
	ReportsHandler "github.com/BryanKMorrow/reports-v2/src/controllers/v1/reports"
	StatusHandler "github.com/BryanKMorrow/reports-v2/src/controllers/v1/status"
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
		"/v1": {
			Routes: routes.Routes{
				routes.Route{"Status", "GET", "/status", StatusHandler.Index},
				routes.Route{"ReportsAll", "GET", "/reports/all", ReportsHandler.All},
				routes.Route{"Report", "GET", "/reports/{registry}/{image}/{tag}", ReportsHandler.One},
				routes.Route{"Reports", "POST", "/reports/images", ReportsHandler.Post},
			},
			Middleware: Middleware,
		},
	}

	return
}
