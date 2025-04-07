package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/centml/platform/ecr-anywhere/pkg/loggers"
	"github.com/centml/platform/ecr-anywhere/pkg/patching"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// These must match the mutating webhook configuration
	managedLabelKey            = "ecr-anywhere.centml.ai/managed"
	managedLabelValue          = "true"
	namespaceEnabledLabelKey   = "ecr-anywhere.centml.ai/namespace"
	namespaceEnabledLabelValue = "enabled"
)

const (
	expiresAtAnnotationKey     = "ecr-anywhere.centml.ai/expires_at"
	markForUpdateAnnotationKey = "ecr-anywhere.centml.ai/marked_for_update_at"
	updatedAnnotationKey       = "ecr-anywhere.centml.ai/updated_at"
)

const (
	// ECR credentials expire after 12 hours, so we'll refresh
	// them after 6 hours to be safe
	expiryThreshold = 6 * time.Hour
)

// DockerConfigJSON represents the structure of the Docker config JSON
type DockerConfigJSON struct {
	Auths map[string]DockerAuth `json:"auths"`
}

// DockerAuth contains the authentication information for a Docker registry
type DockerAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Auth     string `json:"auth"`
}

// ECRClient is an interface for the ECR client, used for mocking
type ECRClient interface {
	GetAuthorizationToken(context.Context, *ecr.GetAuthorizationTokenInput, ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// CredentialInjector is an interface for injecting credentials
// into a secret. This is used for mocking.
type CredentialInjector interface {
	Inject(secret *corev1.Secret) (patching.Operations, error)
	InjectionPermitted(ignoredList []string, metadata *metav1.ObjectMeta) bool
}

// ECRCredentialInjector is a struct that implements the CredentialInjector interface.
// It is used to inject ECR credentials into a secret.
type ecrCredentialInjector struct {
	ecrClient ECRClient
	*loggers.Loggers
}

// NewECRCredentialInjector creates a new ECRCredentialInjector object with the specified ECR client and loggers.
func NewECRCredentialInjector(ecrClient ECRClient, loggers *loggers.Loggers) CredentialInjector {
	return &ecrCredentialInjector{
		ecrClient: ecrClient,
		Loggers:   loggers,
	}
}

// InjectionPermitted determines whether a mutation is required for the specified secret and if so
// which mutation to use
func (ic *ecrCredentialInjector) InjectionPermitted(ignoredList []string, metadata *metav1.ObjectMeta) bool {
	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			ic.InfoLogger.Printf("Skip mutation for %v for it's in special namespace:%v", metadata.Name, metadata.Namespace)
			return false
		}
	}

	labels := metadata.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	ic.InfoLogger.Printf("Labels: %v", labels)

	// Label should be configured in the mutating webhook configuration, but just in case
	// we'll check here as well
	if labels[managedLabelKey] != managedLabelValue {
		ic.InfoLogger.Printf("Interception not permitted for %v/%v due to label %s != %s",
			metadata.Namespace, metadata.Name, managedLabelKey, managedLabelValue)
		return false
	}

	ic.InfoLogger.Printf("Interception for %v/%v has been permitted", metadata.Namespace, metadata.Name)
	return true
}

// Inject injects ECR credentials into the specified secret
func (ecu *ecrCredentialInjector) Inject(secret *corev1.Secret) (patching.Operations, error) {

	// Call the API to get ECR credentials
	res, err := ecu.ecrClient.GetAuthorizationToken(context.Background(), &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		ecu.ErrorLogger.Printf("Failed to get authorization token: %v", err)
		panic(fmt.Errorf("failed to get authorization token: %w", err))
	}
	ecu.InfoLogger.Print("Received authorization data")

	// Obtain token and expiration, not only the first AuthorizationData will be populated,
	// since it can be used with any repo the underlying role has permissions for. Support
	// was removed for specific repo authorization tokens, they kept the data structure
	// the same.
	token, exp := *res.AuthorizationData[0].AuthorizationToken, *res.AuthorizationData[0].ExpiresAt
	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode authorization token: %v", err)
	}

	// Split the token into username and password
	credentials := strings.SplitN(string(decodedToken), ":", 2)
	if len(credentials) != 2 {
		return nil, fmt.Errorf("invalid authorization token format")
	}
	username, password := credentials[0], credentials[1]

	// Create the Docker auth structure
	dockerAuth := DockerAuth{
		Username: username,
		Password: password,
		Auth:     token,
	}

	// Create the Docker config JSON
	dockerConfig := DockerConfigJSON{
		Auths: map[string]DockerAuth{
			*res.AuthorizationData[0].ProxyEndpoint: dockerAuth,
		},
	}

	// Marshal the Docker config JSON to a string
	dcj, err := json.Marshal(dockerConfig)
	if err != nil {
		log.Fatalf("failed to marshal Docker config JSON: %v", err)
	}

	// Base64 encode the Docker config JSON
	dcjb64 := base64.StdEncoding.EncodeToString(dcj)

	var patches patching.Operations
	expstr := exp.Format(time.RFC3339)

	// Annotations might not exist for new secrets
	if secret.Annotations == nil {
		// create empty annotations patch
		patches.Add(&patching.Operation{
			Op:    "add",
			Path:  "/metadata/annotations",
			Value: map[string]string{},
		})
		// set the annotations to the empty map so don't need to nil check below
		secret.Annotations = map[string]string{}
	}

	// Add or replace the expiresAt annotation
	if _, ok := secret.Annotations[expiresAtAnnotationKey]; !ok {
		ecu.InfoLogger.Printf("Adding annotation %s = %s to secret %s/%s", expiresAtAnnotationKey, expstr, secret.Namespace, secret.Name)
		patches.Add(&patching.Operation{
			Op:    "add",
			Path:  "/metadata/annotations/" + patchFriendly(expiresAtAnnotationKey),
			Value: expstr,
		})
	} else {
		ecu.InfoLogger.Printf("Replacing annotation %s in secret %s/%s", expiresAtAnnotationKey, secret.Namespace, secret.Name)
		patches.Add(&patching.Operation{
			Op:    "replace",
			Path:  "/metadata/annotations/" + patchFriendly(expiresAtAnnotationKey),
			Value: exp.Format(time.RFC3339),
		})
	}

	if _, ok := secret.Annotations[updatedAnnotationKey]; !ok {
		ecu.InfoLogger.Printf("Adding annotation %s = %s to secret %s/%s", updatedAnnotationKey, time.Now().Format(time.RFC3339), secret.Namespace, secret.Name)
		patches.Add(&patching.Operation{
			Op:    "add",
			Path:  "/metadata/annotations/" + patchFriendly(updatedAnnotationKey),
			Value: time.Now().Format(time.RFC3339),
		})
	} else {
		ecu.InfoLogger.Printf("Replacing annotation %s in secret %s/%s", updatedAnnotationKey, secret.Namespace, secret.Name)
		patches.Add(&patching.Operation{
			Op:    "replace",
			Path:  "/metadata/annotations/" + patchFriendly(updatedAnnotationKey),
			Value: time.Now().Format(time.RFC3339),
		})
	}

	// Create the patch operation for the secret
	ecu.InfoLogger.Printf("Adding patch operation for secret %s/%s", secret.Namespace, secret.Name)
	patches.Add(&patching.Operation{
		Op:   "replace",
		Path: "/data",
		Value: map[string]string{
			".dockerconfigjson": dcjb64,
		},
	})
	return patches, nil
}

// CredentialRefreshRequester is an interface for requesting credential refreshes.
// This is used for mocking.
type CredentialRefreshRequester interface {
	RequestRefreshes(force bool) error
}

// k8sCredentialRefreshRequester is a struct that implements the
// CredentialRefreshRequester interface.
type k8sCredentialRefreshRequester struct {
	*loggers.Loggers
	clientset kubernetes.Interface
}

// NewK8sCredentialRefreshRequester creates a new CredentialRefreshRequester
// with the specified Kubernetes clientset and loggers.
func NewK8sCredentialRefreshRequester(clientset kubernetes.Interface,
	loggers *loggers.Loggers) CredentialRefreshRequester {
	return &k8sCredentialRefreshRequester{
		Loggers:   loggers,
		clientset: clientset,
	}
}

// RequestRefreshes requests credential refreshes for all secrets that need to
// be updated. It does this by checking the expiration time of each secret and
// then marking it  with an annotation if it needs to be updated. The actual
// update is done by the mutating webhook.
func (kcr *k8sCredentialRefreshRequester) RequestRefreshes(force bool) error {

	kcr.InfoLogger.Printf("Looking for credentials to refresh, force=%v\n", force)

	// find labeled namespaces
	namespaces, err := kcr.clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", namespaceEnabledLabelKey, namespaceEnabledLabelValue),
	})
	if err != nil {
		kcr.ErrorLogger.Printf("error listing namespaces: %s\n", err.Error())
		return err
	}

	kcr.InfoLogger.Printf("Found %d namespaces with label %s=%s\n", len(namespaces.Items), namespaceEnabledLabelKey, namespaceEnabledLabelValue)

	// if there are any issues below they will be logged and success will be marked false
	// but we will continue to process the remaining secrets
	success := true

	for _, namespace := range namespaces.Items {
		// get all secrets that have the managed label
		secrets, err := kcr.clientset.CoreV1().Secrets(namespace.Name).List(context.TODO(), metav1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", managedLabelKey, managedLabelValue),
		})
		if err != nil {
			// TODO Maybe just fatal?
			kcr.ErrorLogger.Printf("error listing secrets in namespace %s\n", err.Error())
			return err
		}

		kcr.InfoLogger.Printf("Found %d secrets with label %s=%s\n", len(secrets.Items), managedLabelKey, managedLabelValue)

		for _, secret := range secrets.Items {
			if secret.Annotations == nil {
				secret.Annotations = map[string]string{}
			}

			if expires, ok := secret.Annotations[expiresAtAnnotationKey]; !ok {
				kcr.WarnLogger.Printf("Managed secret %s/%s does not have an expiration annotation\n", secret.Namespace, secret.Name)
				setRequestAnnotation(kcr.clientset, &secret)
			} else {

				// expires at
				expat, err := time.Parse(time.RFC3339, expires)
				if err != nil {
					kcr.ErrorLogger.Printf("error parsing expiration time for secret %s/%s: %s\n", secret.Namespace, secret.Name, err.Error())
					success = false
					continue
				}

				// if the secret will expire within the expiryThreshold, update it
				if time.Now().After(expat.Add(-1*expiryThreshold)) || force {
					kcr.InfoLogger.Printf("Updating secret %s/%s\n", secret.Namespace, secret.Name)
					setRequestAnnotation(kcr.clientset, &secret)
				} else {
					kcr.InfoLogger.Printf("Secret %s/%s is not due for update, it expires at %s\n", secret.Namespace, secret.Name, expat.Format(time.RFC3339))
				}
			}
		}
	}
	if !success {
		return fmt.Errorf("some secrets failed to update, see logs for details")
	}

	return nil
}

// setRequestAnnotation sets the annotation on the secret to indicate that
// it should be updated
func setRequestAnnotation(clientset kubernetes.Interface, secret *corev1.Secret) {
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}

	// this sets the annotation to the current time indicating that the secret should be updated
	secret.Annotations[markForUpdateAnnotationKey] = time.Now().Format(time.RFC3339)
	_, err := clientset.CoreV1().Secrets(secret.Namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		fmt.Printf("error updating secret %s/%s: %s\n", secret.Namespace, secret.Name, err.Error())
	}
}

// patchFriendly replaces any / with ~1 in a string for use in a JSON patch
func patchFriendly(str string) string {
	return strings.ReplaceAll(str, "/", "~1")
}
