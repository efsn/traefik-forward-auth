package internal

import (
	"os"

	"github.com/sirupsen/logrus"
)

var logger *logrus.Logger

// NewDefaultLogger build default logger
func NewDefaultLogger() *logrus.Logger {
	logger = logrus.StandardLogger()
	logrus.SetOutput(os.Stdout)

	switch conf.LogFormat {
	case "pretty":
		break
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{})
	default:
		logrus.SetFormatter(&logrus.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
	}

	switch conf.LogLevel {
	case "trace":
		logrus.SetLevel(logrus.TraceLevel)
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	// case "warning":
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	case "panic":
		logrus.SetLevel(logrus.PanicLevel)
	default:
		logrus.SetLevel(logrus.WarnLevel)
	}
	return logger
}
