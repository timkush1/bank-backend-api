package main

import (
	"log"
	"net/http"

	"f5.com/ha/pkg"
)

func main() {
	// Public routes without authentication
	http.HandleFunc("/register", pkg.Register)
	http.HandleFunc("/login", pkg.Login)

	// applying middleware to routes
	http.HandleFunc("/accounts", pkg.RoleMiddleware("admin", pkg.AccountsHandler))
	http.HandleFunc("/balance",  pkg.Auth(pkg.BalanceHandler))             

	port := ":8080"
	log.Printf("Starting server on port %s...", port)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
