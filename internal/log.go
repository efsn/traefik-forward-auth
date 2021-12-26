package internal

import (
	"os"

	"github.com/sirupsen/logrus"
)

var logger = NewDefaultLogger()

// GetLogger get logger
func GetLogger() *logrus.Logger {
	return logger
}

// NewDefaultLogger build default logger
func NewDefaultLogger() *logrus.Logger {
	log := logrus.StandardLogger()
	log.SetOutput(os.Stdout)
	if config != nil {
		setupLogger(config)
	}
	return log
}

func setupLogger(cfg *Config) {
	switch cfg.LogFormat {
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

	switch cfg.LogLevel {
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
}
