package main

import (
	"log"
	"net/http"
)

func main() {
	// starts the server on port 8000
	log.Fatal(http.ListenAndServe(":8000", nil))
}
