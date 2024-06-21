package webhook

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"testing"

	"github.com/centml/platform/ecr-anywhere/pkg/loggers"
	"github.com/centml/platform/ecr-anywhere/pkg/patching"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// MockCredentialInjector is a mock implementation of the CredentialInjector interface
type MockCredentialInjector struct {
	mock.Mock
}

// Inject is a mock implementation of the Inject method
func (m *MockCredentialInjector) Inject(secret *corev1.Secret) (patching.Operations, error) {
	args := m.Called(secret)
	if args.Get(0) != nil {
		return args.Get(0).(patching.Operations), args.Error(1)
	}
	return nil, args.Error(1)
}

// InjectionPermitted is a mock implementation of the InjectionPermitted method
func (m *MockCredentialInjector) InjectionPermitted(ignoredList []string, metadata *metav1.ObjectMeta) bool {
	args := m.Called(ignoredList, metadata)
	return args.Bool(0)
}

// TestWebhookServer_process tests the process method
func TestWebhookServer_process(t *testing.T) {

	mockci := &MockCredentialInjector{}

	whsvr := &WebhookServer{
		Loggers:            loggers.NewLoggers(log.New(io.Discard, "", 0), log.New(io.Discard, "", 0), log.New(io.Discard, "", 0)),
		CredentialInjector: mockci,
	}

	tests := []struct {
		name             string
		admissionReview  *admissionv1.AdmissionReview
		secret           corev1.Secret
		setupMocks       func()
		expectedResponse *admissionv1.AdmissionResponse
	}{
		{
			name: "unmarshal error",
			admissionReview: &admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{Raw: []byte("invalid")},
				},
			},
			setupMocks: func() {
			},
			expectedResponse: &admissionv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: "invalid character 'i' looking for beginning of value",
				},
			},
		},
		{
			name: "not intercepting secret",
			admissionReview: &admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{Raw: func() []byte {
						s := corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-secret"},
						}
						b, _ := json.Marshal(s)
						return b
					}()},
				},
			},
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-secret"},
			},
			setupMocks: func() {
				mockci.On("InjectionPermitted", ignoredNamespaces, mock.Anything).Return(false).Once()
			},
			expectedResponse: &admissionv1.AdmissionResponse{
				Allowed: true,
			},
		},
		{
			name: "credential injection error",
			admissionReview: &admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{Raw: func() []byte {
						s := corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-secret"},
						}
						b, _ := json.Marshal(s)
						return b
					}()},
				},
			},
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-secret"},
			},
			setupMocks: func() {
				mockci.On("InjectionPermitted", ignoredNamespaces, mock.Anything).Return(true).Once()
				mockci.On("Inject", mock.Anything).Return(nil, fmt.Errorf("credential injection error")).Once()
			},
			expectedResponse: &admissionv1.AdmissionResponse{
				Result: &metav1.Status{
					Message: fmt.Errorf("credential injection error").Error(),
				},
			},
		},
		{
			name: "successful injection",
			admissionReview: &admissionv1.AdmissionReview{
				Request: &admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{Raw: func() []byte {
						s := corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-secret"},
						}
						b, _ := json.Marshal(s)
						return b
					}()},
				},
			},
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-secret"},
			},
			setupMocks: func() {
				mockci.On("InjectionPermitted", ignoredNamespaces, mock.Anything).Return(true).Once()
				mockci.On("Inject", mock.Anything).Return(patching.Operations{
					&patching.Operation{
						Op:    "add",
						Path:  "/data",
						Value: "value",
					},
				}, nil)
			},
			expectedResponse: &admissionv1.AdmissionResponse{
				Allowed: true,
				Patch:   []byte(`[{"op":"add","path":"/data","value":"value"}]`),
				PatchType: func() *admissionv1.PatchType {
					pt := admissionv1.PatchTypeJSONPatch
					return &pt
				}(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			response := whsvr.process(tt.admissionReview)
			assert.Equal(t, tt.expectedResponse, response)
			mockci.AssertExpectations(t)
		})
	}
}
