package router

import (
	"net/http"

	"github.com/BryanKMorrow/aqua-reports/pkg/types/routes"
	V1SubRoutes "github.com/BryanKMorrow/aqua-reports/src/controllers/v1/router"

	"github.com/gorilla/mux"
)

// Router - Mux router struct
type Router struct {
	Router *mux.Router
}

// Init - Initialize the router and get the route and subroutes
func (r *Router) Init() {
	r.Router.Use(Middleware)
	r.Router.PathPrefix("/reports/").Handler(http.StripPrefix("/reports/", http.FileServer(http.Dir("reports"))))
	baseRoutes := GetRoutes()
	for _, route := range baseRoutes {
		r.Router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandlerFunc)
	}

	v1SubRoutes := V1SubRoutes.GetRoutes()
	for name, pack := range v1SubRoutes {
		r.AttachSubRouterWithMiddleware(name, pack.Routes, pack.Middleware)
	}
}

// AttachSubRouterWithMiddleware - yes
func (r *Router) AttachSubRouterWithMiddleware(path string, subroutes routes.Routes, middleware mux.MiddlewareFunc) (SubRouter *mux.Router) {

	SubRouter = r.Router.PathPrefix(path).Subrouter()
	SubRouter.Use(middleware)

	for _, route := range subroutes {
		SubRouter.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandlerFunc)
	}

	return
}

// NewRouter - return the router
func NewRouter() (r Router) {
	r.Router = mux.NewRouter().StrictSlash(true)
	return
}
