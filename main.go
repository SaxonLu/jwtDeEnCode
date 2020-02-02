package main

import (
	"jwtDeEnCode/handler"
	"log"
	"net/http"
	"github.com/codegangsta/negroni"
)

func main() {
	StartServer()
}

func StartServer() {

	http.HandleFunc("/encode", handler.Encode)

	http.Handle("/decode", negroni.New(
		negroni.HandlerFunc(handler.ValidateTokenMiddleware),
		negroni.Wrap(http.HandlerFunc(handler.ProtectedHandler)),
	))

	port := ":8090"
	log.Println("Now listening...localhost//" + port)
	http.ListenAndServe(port, nil)
}