package server

import(
	"log"
	"net/http"
	"csrf/middleware"
)

func StartServer(hostname string, port string) error{
	host := hostname + ":" + port

	log.Println("Listening on: %s", host)

	handler := middleware.NewHandler()

	http.Handler("/", handler)
	return http.ListenAndServe(host, nil)
}