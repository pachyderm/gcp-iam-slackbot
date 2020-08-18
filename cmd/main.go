package main

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	"pachyderm.io/gcpiamslack"
)

func main() {
	http.HandleFunc("/actions", gcpiamslack.ActionHandler)
	http.HandleFunc("/slash", gcpiamslack.SlashHandler)
	log.Info("Server listening on :8080")
	http.ListenAndServe(":8080", nil)
}
