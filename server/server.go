package server

import(
	"log"
	"net/http"
	"csrf/server/middleware"
)

func StartServer(hostname string, port string) error{
	host := hostname + ":" + port

	log.Println("Listening on: %s", host)

	handler := middleware.NewHandler()

	http.Handle("/", handler)
	return http.ListenAndServe(host, nil)
}