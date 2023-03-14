package remover

import (
	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
	"github.com/snowzach/rotatefilehook"
	"time"
)

type logger struct{ *logrus.Logger }

func (l *logger) Say(msg string) {
	l.Info(msg)
}
func (l *logger) Sayf(fmt string, args ...interface{}) {
	l.Infof(fmt, args)
}
func (l *logger) SayWithField(msg string, k string, v interface{}) {
	l.WithField(k, v).Info(msg)
}
func (l *logger) SayWithFields(msg string, fields map[string]interface{}) {
	l.WithFields(fields).Info(msg)
}

func NewLogger() *logger {

	logLevel := logrus.DebugLevel
	log := logrus.New()
	log.SetLevel(logLevel)

	rotateFileHook, err := rotatefilehook.NewRotateFileHook(rotatefilehook.RotateFileConfig{
		Filename:   "logs/console.log",
		MaxSize:    50, // megabytes
		MaxBackups: 3,  // amouts
		MaxAge:     28, //days
		Level:      logLevel,
		Formatter: &logrus.JSONFormatter{
			TimestampFormat: time.RFC822,
		},
	})

	if err != nil {
		logrus.Fatalf("Failed to initialize file rotate hook: %v", err)
	}

	log.SetOutput(colorable.NewColorableStdout())

	log.SetFormatter(&logrus.TextFormatter{
		PadLevelText:     true,
		ForceColors:      true,
		DisableTimestamp: true,
	})

	log.AddHook(rotateFileHook)

	return &logger{log}
}
