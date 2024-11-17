package main

import (
	"fmt"
	"log"
	"net/http"

	api "f5.com/ha/pkg"
)

func main() {
	http.HandleFunc("/register", api.Register)
	http.HandleFunc("/login", api.Login)
	http.HandleFunc("/accounts", api.Auth(api.AccountsHandler))
	http.HandleFunc("/balance", api.Auth(api.BalanceHandler))

	fmt.Println("Server starting on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
