package app

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/BryanKMorrow/aqua-reports/src/system/router"
	"github.com/gorilla/handlers"
)

// ModeFlag - command line parameter to determine where to get the arguments
var ModeFlag string

// URLFlag - command line parameter to determine where to get the Aqua CSP URL argument
var URLFlag string

// UserFlag - command line parameter to determine where to get the CSP user argument
var UserFlag string

// PasswordFlag - command line parameter to determine where to get the CSP password argument
var PasswordFlag string

// PortFlag - command line parameter to determine where to get the application port argument
var PortFlag int

func init() {
	flag.StringVar(&ModeFlag, "mode", "cli", "cli or container")
	flag.StringVar(&URLFlag, "url", "", "Address to Aqua CSP web console")
	flag.StringVar(&UserFlag, "user", "", "Aqua CSP API username")
	flag.StringVar(&PasswordFlag, "password", "", "Aqua CSP API user password")
	flag.IntVar(&PortFlag, "port", 0, "Specify the port for this application")
	flag.Parse()
}

// Server - structure for the API server
type Server struct {
	port string
}

// NewServer - Instantiate a Server struct
func NewServer() Server {
	return Server{}
}

// Init all vals
func (s *Server) Init(port string) {
	log.Println("Initializing server...")
	s.port = ":" + port
}

// Start the server
func (s *Server) Start() {
	log.Println("Starting server on port" + s.port)

	r := router.NewRouter()

	r.Init()

	handler := handlers.LoggingHandler(os.Stdout, handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedMethods([]string{"GET", "PUT", "PATCH", "POST", "DELETE", "OPTIONS"}),
		handlers.AllowedHeaders([]string{"Content-Type", "Origin", "Cache-Control", "X-App-Token"}),
		handlers.ExposedHeaders([]string{""}),
		handlers.MaxAge(1000),
		handlers.AllowCredentials(),
	)(r.Router))
	handler = handlers.RecoveryHandler(handlers.PrintRecoveryStack(true))(handler)

	newServer := &http.Server{
		Handler:      handler,
		Addr:         "0.0.0.0" + s.port,
		WriteTimeout: 10 * time.Minute,
		ReadTimeout:  30 * time.Second,
	}

	log.Fatal(newServer.ListenAndServe())
}
