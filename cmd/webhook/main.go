package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/centml/platform/ecr-anywhere/pkg/credentials"
	"github.com/centml/platform/ecr-anywhere/pkg/loggers"
	"github.com/centml/platform/ecr-anywhere/pkg/webhook"
	"github.com/spf13/viper"
)

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
	warnLogger  *log.Logger
)

func init() {
	// init loggers
	infoLogger = log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	warnLogger = log.New(os.Stderr, "WARN: ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	viper.AutomaticEnv()
	viper.SetDefault("PORT", 8443)
	viper.SetDefault("CERT_FILE", "/etc/webhook/certs/tls.crt")
	viper.SetDefault("KEY_FILE", "/etc/webhook/certs/tls.key")

}

func main() {

	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	ecrc := ecr.NewFromConfig(awsCfg)

	lgz := loggers.NewLoggers(infoLogger, warnLogger, errorLogger)

	cfg := &webhook.WebhookServerConfig{
		Port:               viper.GetInt("PORT"),
		CertPEM:            viper.GetString("CERT_FILE"),
		KeyPEM:             viper.GetString("KEY_FILE"),
		CredentialInjector: credentials.NewECRCredentialInjector(ecrc, lgz),
		Loggers:            lgz,
	}
	whsvr := webhook.NewCredentialWebhookServer(cfg)

	// start webhook server in new go rountine
	go func() {
		if err := whsvr.Start(); err != nil {
			errorLogger.Fatalf("Failed to start webhook server: %v", err)
		}
	}()

	// listening OS shutdown singal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	infoLogger.Printf("Got OS shutdown signal, shutting down webhook server gracefully...")
	whsvr.Stop()
}
