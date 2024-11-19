package main

import (
	"log"
	"os"

	"github.com/centml/platform/ecr-anywhere/pkg/credentials"
	"github.com/centml/platform/ecr-anywhere/pkg/loggers"
	"github.com/spf13/viper"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func init() {
	viper.AutomaticEnv()

	// TODO this can be better
	// CENTML_FORCE
	viper.SetEnvPrefix("CENTML")
	viper.SetDefault("FORCE", false)
}

func getRestConfig() *rest.Config {
	var kcfg *rest.Config
	var err error
	if viper.GetString("KUBECONFIG") == "" {
		// TODO loggers
		kcfg, err = rest.InClusterConfig()
		if err != nil {
			log.Fatalf("Failed to load in-cluster kubeconfig: %v", err)
		}
	} else {
		kcfg, err = clientcmd.BuildConfigFromFlags("", viper.GetString("KUBECONFIG"))
		if err != nil {
			log.Fatalf("Failed to load kubeconfig: %v", err)
		}
	}
	return kcfg

}

func main() {

	kcfg := getRestConfig()
	clientset, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		log.Fatalf("Failed to create kubernetes clientset: %v", err)
	}

	loggers := loggers.NewLoggers(log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile), log.New(os.Stderr, "WARN: ", log.Ldate|log.Ltime|log.Lshortfile), log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile))
	r := credentials.NewK8sCredentialRefreshRequester(clientset, loggers)

	// TODO stop hardcoding
	err = r.RequestRefreshes(true)
	if err != nil {
		log.Fatalf("Failed to request credential refreshes: %v", err)
	}
}
