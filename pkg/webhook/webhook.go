package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/centml/platform/ecr-anywhere/pkg/credentials"
	"github.com/centml/platform/ecr-anywhere/pkg/loggers"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme     = runtime.NewScheme()
	codecs            = serializer.NewCodecFactory(runtimeScheme)
	deserializer      = codecs.UniversalDeserializer()
	webhookInjectPath = "/sync"
)

// ignoredNamespaces is a list of namespaces to ignore when processing secrets.
var ignoredNamespaces = []string{
	// kube-system and kube-public are ignored by default
	// Note, the webhook also has a namespace label selector and an object label selector
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

// WebhookServer contains the configuration for the webhook server. It's used as a receiver for various
// methods such as Start and Stop.
type WebhookServer struct {
	*loggers.Loggers
	credentials.CredentialInjector
	server          *http.Server
	certPEM, keyPEM string
}

// WebhookServerConfig is the configuration for the webhook server. It contains the port to listen on,
// the path to the certificate and key files, the MultiConfig object containing the sidecar configurations,
// and the loggers for info, warning, and error messages.
type WebhookServerConfig struct {
	Port               int
	CertPEM            string
	KeyPEM             string
	Loggers            *loggers.Loggers
	CredentialInjector credentials.CredentialInjector
}

// NewCredentialWebhookServer creates a new WebhookServer object with the specified configuration.
func NewCredentialWebhookServer(cfg *WebhookServerConfig) *WebhookServer {

	whsvr := &WebhookServer{
		server: &http.Server{
			Addr: fmt.Sprintf(":%v", cfg.Port),
			TLSConfig: &tls.Config{
				// each request we retrieve the certs incase they have been rotated
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					cert, err := tls.LoadX509KeyPair(cfg.CertPEM, cfg.KeyPEM)
					if err != nil {
						return nil, err
					}
					return &cert, nil
				},
			},
		},
		Loggers:            cfg.Loggers,
		CredentialInjector: cfg.CredentialInjector,
	}

	// define http server and server handler
	mux := http.NewServeMux()
	mux.HandleFunc(webhookInjectPath, whsvr.Serve)
	whsvr.server.Handler = mux

	return whsvr
}

// process handles the admission request and returns the admission response.
func (whs *WebhookServer) process(ar *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	req := ar.Request
	var secret corev1.Secret
	if err := json.Unmarshal(req.Object.Raw, &secret); err != nil {
		whs.ErrorLogger.Printf("Could not unmarshal raw object: %v", err)
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	whs.InfoLogger.Printf("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, secret.Name, req.UID, req.Operation, req.UserInfo)

	// determine whether to intercept secret or ignore it
	icept := whs.InjectionPermitted(ignoredNamespaces, &secret.ObjectMeta)
	if !icept {
		// ignore
		whs.InfoLogger.Printf("Not intercepting %s/%s", secret.Namespace, secret.Name)
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}
	}

	// inject the credentials OR error out, thus secret creation/updates fail
	// if there is an error
	patches, err := whs.Inject(&secret)
	if err != nil {
		whs.ErrorLogger.Printf("Could not process the secret: %s", err.Error())
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	pjb, err := json.Marshal(patches)
	if err != nil {
		whs.ErrorLogger.Printf("Could not marshal patches: %s", err.Error())
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	whs.InfoLogger.Printf("populating ECR image pull secret for %s/%s", secret.Namespace, secret.Name)
	pt := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		Allowed:   true,
		Patch:     pjb,
		PatchType: &pt,
	}
}

// Serve method for webhook `server`
func (whs *WebhookServer) Serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := io.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		whs.ErrorLogger.Println("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		whs.ErrorLogger.Printf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	// decode the admission request
	var admissionResponse *admissionv1.AdmissionResponse
	ar := admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		whs.ErrorLogger.Printf("Can't decode body: %v", err)
		admissionResponse = &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		// process the secret sent in, active if appropriatea
		admissionResponse = whs.process(&ar)
	}

	// encode the admission response
	admissionReview := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
	}

	// set the response
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	// encode the response
	resp, err := json.Marshal(admissionReview)
	if err != nil {
		whs.ErrorLogger.Printf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}

	// write the response
	whs.InfoLogger.Printf("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		whs.ErrorLogger.Printf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

// Start method for webhook server. It blocks until the server is stopped.
func (whs *WebhookServer) Start() error {
	whs.InfoLogger.Printf("Starting webhook server...\n")
	return whs.server.ListenAndServeTLS(whs.certPEM, whs.keyPEM)
}

// Stop method for webhook server. It stops the server gracefully.
func (whs *WebhookServer) Stop() {
	whs.server.Shutdown(context.Background())
}
