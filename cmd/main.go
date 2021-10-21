package cmd

import (
	"fmt"
	"net/http"

	"github.com/efsn/traefik-forward-auth/internal"
)

func main() {
	conf := internal.NewGlobalConf()
	logger := internal.NewDefaultLogger()
	conf.Validate()
	server := internal.NewServer()
	http.HandleFunc("/", server.DefaultHandler)
	logger.WithField("conf", conf).Debug("Starting with conf")
	logger.Infof("Listening on: %d", conf.Port)
	logger.Info(http.ListenAndServe(fmt.Sprintf(":%d", conf.Port), nil))
}
