package router

import (
	"simple_jwt_based_auth/controllers"

	"github.com/gorilla/mux"
)

func Router() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/login", controllers.LogIn).Methods("POST", "OPTIONS")
	router.HandleFunc("/refresh", controllers.Refresh).Methods("POST", "OPTIONS")
	router.HandleFunc("/items", controllers.GetItems).Methods("GET", "OPTIONS")

	return router
}
