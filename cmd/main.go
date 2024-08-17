package main

import (
	"fmt"
	"log"
	"net/http"

	"simple_jwt_based_auth/router"
)

func main() {
	r := router.Router()

	fmt.Printf("Starting server at port 8080\n")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("Could not start server: %s\n", err.Error())
	}
}
