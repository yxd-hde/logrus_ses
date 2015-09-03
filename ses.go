package logrus_ses

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"

	log "github.com/Sirupsen/logrus"
)

const (
	SESServer = "email-smtp.us-east-1.amazonaws.com"
	SESPort   = 587
)

var (
	SESServerAddr = SESServer + ":" + strconv.Itoa(SESPort)

	JSONFormatter = &log.JSONFormatter{}

	getUsername = func() string {
		return os.Getenv("SES_ACCESS_KEY_ID")
	}

	getPassword = func() string {
		return os.Getenv("SES_SECRET_ACCESS_KEY")
	}

	getHostname = func() string {
		return os.Getenv("EXTERNAL_DOMAIN")
	}

	getIP = func() string {
		return os.Getenv("EXTERNAL_IP")
	}

	getFrom = func() string {
		return os.Getenv("SES_LOG_NOTIFICATION_FROM")
	}

	getTo = func() string {
		return os.Getenv("SES_LOG_NOTIFICATION_TO")
	}
)

// SESHook to sends logs by email with AWS SES.
type SESHook struct {
	log.Hook

	// AppName is the application name of the log
	AppName string

	// From and to of the envelope
	From *mail.Address
	To   *mail.Address

	// SES authentication
	Auth smtp.Auth

	// Level above this (including this level) message will trigger
	// the hook.
	Level log.Level
}

// NewSESHook creates a hook to be added to an instance of logger.
func NewSESHook(appName string, level log.Level) (*SESHook, error) {
	// Validate sender and recipient
	sender, err := mail.ParseAddress(getFrom())
	if err != nil {
		return nil, err
	}
	receiver, err := mail.ParseAddress(getTo())
	if err != nil {
		return nil, err
	}

	// Get SES specific username and password
	username := getUsername()
	if len(username) == 0 {
		return nil, errors.New("SES_ACCESS_KEY_ID not set.")
	}
	password := getPassword()
	if len(password) == 0 {
		return nil, errors.New("SES_SECRET_ACCESS_KEY not set.")
	}

	return &SESHook{
		AppName: appName,
		From:    sender,
		To:      receiver,
		Auth:    smtp.PlainAuth("", username, password, SESServer),
		Level:   level,
	}, nil
}

// Fire is called when a log event is fired.
func (hook *SESHook) Fire(entry *log.Entry) error {
	message := hook.createMessage(entry)

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	err := smtp.SendMail(
		SESServerAddr,
		hook.Auth,
		hook.From.Address,
		[]string{hook.To.Address},
		message,
	)
	if err != nil {
		return err
	}
	return nil
}

// Levels returns the available logging levels.
func (hook *SESHook) Levels() (levels []log.Level) {
	for _, l := range []log.Level{
		log.PanicLevel,
		log.FatalLevel,
		log.ErrorLevel,
		log.WarnLevel,
		log.InfoLevel,
		log.DebugLevel,
	} {
		// PanicLevel is 0 and it goes up.
		if l <= hook.Level {
			levels = append(levels, l)
		}
	}
	return
}

const template = `Subject: [%s][%s] %s on %s ( %s )

Log entry:

%s

--
From %s with love.
`

func getEntry(entry *log.Entry) []byte {
	buf := new(bytes.Buffer)
	logBuf, err := JSONFormatter.Format(entry)
	if err != nil {
		fmt.Fprintf(buf, "Failed to format log entry correctly.\n"+
			" Please check the log file on server.")
	} else {
		json.Indent(buf, logBuf, "", "\t")
	}
	return buf.Bytes()
}

func (hook *SESHook) createMessage(entry *log.Entry) []byte {
	message := new(bytes.Buffer)

	fmt.Fprintf(message, template, entry.Time, entry.Level.String(),
		hook.AppName, getHostname(), getIP(), getEntry(entry),
		hook.AppName)

	return message.Bytes()
}
