package main

import (
	"fmt"
	"net/http"

	"github.com/efsn/traefik-forward-auth/internal"
)

func main() {
	config := internal.NewGlobalConfig().Validate()
	server := internal.NewServer()
	logger := internal.GetLogger()
	http.HandleFunc("/", server.DefaultHandler)
	// logger.WithField("config", config).Debug("Starting with config")
	logger.Debugf("Starting server on %s", config)
	logger.Infof("Listening on: %d", config.Port)
	logger.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
