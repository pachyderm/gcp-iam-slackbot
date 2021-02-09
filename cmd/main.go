package main

import (
	"gcpiamslack"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func main() {
	log.Info("Starting http server on :8080...")
	http.HandleFunc("/healthz", gcpiamslack.HealthzHandler)
	http.HandleFunc("/ActionHandler", gcpiamslack.ActionHandler)
	http.HandleFunc("/SlashHandler", gcpiamslack.SlashHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
