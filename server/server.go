package server

import (
	"log"
	"net/http"

	"github.com/simar/golang-csrf-project/server/middleware"
)

func StartServer(hosthame string, port string)error{
	host := hosthame + ":" +port
	log.Println("Listening on: %s",host)
	handler := middleware.NewHandler()

	http.Handle("/",handler)
	return http.ListenAndServe(host,nil)
	
}