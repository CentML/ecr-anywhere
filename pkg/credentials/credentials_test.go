package credentials

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/centml/platform/ecr-anywhere/pkg/loggers"
	"github.com/centml/platform/ecr-anywhere/pkg/patching"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// MockECRClient is a mock implementation of the ECRClient interface for testing
type MockECRClient struct {
	mock.Mock
}

// GetAuthorizationToken provides a mock function with given fields: ctx, input, opts
func (m *MockECRClient) GetAuthorizationToken(ctx context.Context, input *ecr.GetAuthorizationTokenInput, opts ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	args := m.Called(ctx, input, opts)

	if args.Get(0) != nil {
		return args.Get(0).(*ecr.GetAuthorizationTokenOutput), args.Error(1)
	} else {
		return nil, args.Error(1)
	}
}

// TestInjectionPermitted tests the InjectionPermitted method of ecrCredentialInjector
func TestInjectionPermitted(t *testing.T) {

	mockECRClient := new(MockECRClient)
	dl := log.New(io.Discard, "", 0)
	injector := NewECRCredentialInjector(mockECRClient, loggers.NewLoggers(dl, dl, dl))

	tests := []struct {
		name        string
		ignoredList []string
		metadata    *metav1.ObjectMeta
		expected    bool
	}{
		{
			name:        "Injection not permitted for ignored namespace",
			ignoredList: []string{"kube-system", "default"},
			metadata: &metav1.ObjectMeta{
				Namespace: "kube-system",
				Name:      "test-pod",
				Labels:    map[string]string{managedLabelKey: managedLabelValue},
			},
			expected: false,
		},
		{
			name:        "Injection not permitted for missing managed label",
			ignoredList: []string{},
			metadata: &metav1.ObjectMeta{
				Namespace: "default",
				Name:      "test-pod",
				Labels:    map[string]string{"some-label": "some-value"},
			},
			expected: false,
		},
		{
			name:        "Injection permitted",
			ignoredList: []string{"kube-system"},
			metadata: &metav1.ObjectMeta{
				Namespace: "default",
				Name:      "test-pod",
				Labels:    map[string]string{managedLabelKey: managedLabelValue},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := injector.InjectionPermitted(tt.ignoredList, tt.metadata)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestInject tests the Inject method of ecrCredentialInjector
func TestInject(t *testing.T) {
	mockECRClient := new(MockECRClient)

	dl := log.New(io.Discard, "", 0)
	injector := NewECRCredentialInjector(mockECRClient, loggers.NewLoggers(dl, dl, dl))

	authorizationToken := base64.StdEncoding.EncodeToString([]byte("username:password"))
	badAuthorizationToken := "&"
	proxyEndpoint := "https://proxy.example.com"
	expirationTime := time.Now().Add(1 * time.Hour)

	anyti := mock.AnythingOfType("*ecr.GetAuthorizationTokenInput")

	tests := []struct {
		name            string
		setupMock       func()
		secret          *corev1.Secret
		expectedError   string
		expectedPatches patching.Operations
	}{
		{
			name: "GetAuthorizationToken fails",
			setupMock: func() {
				mockECRClient.On("GetAuthorizationToken", mock.Anything, anyti, mock.Anything).Return(nil, fmt.Errorf("failed to get token")).Once()
			},
			secret:        &corev1.Secret{},
			expectedError: "failed to get authorization token: failed to get token",
		},
		{
			name: "Authorization token decoding fails",
			setupMock: func() {

				mockECRClient.On("GetAuthorizationToken", mock.Anything, anyti, mock.Anything).Return(&ecr.GetAuthorizationTokenOutput{
					AuthorizationData: []types.AuthorizationData{
						{
							AuthorizationToken: &badAuthorizationToken,
							ExpiresAt:          &expirationTime,
							ProxyEndpoint:      &proxyEndpoint,
						},
					},
				}, nil).Once()
			},
			secret:        &corev1.Secret{},
			expectedError: "failed to decode authorization token: illegal base64 data at input byte 0",
		},
		{
			name: "Authorization token format is invalid",
			setupMock: func() {
				token := base64.StdEncoding.EncodeToString([]byte("invalidtoken"))
				mockECRClient.On("GetAuthorizationToken", mock.Anything, anyti, mock.Anything).Return(&ecr.GetAuthorizationTokenOutput{
					AuthorizationData: []types.AuthorizationData{
						{
							AuthorizationToken: &token,
							ExpiresAt:          &expirationTime,
							ProxyEndpoint:      &proxyEndpoint,
						},
					},
				}, nil).Once()
			},
			secret:        &corev1.Secret{},
			expectedError: "invalid authorization token format",
		},
		{
			name: "Successful injection - add expiresAt and updated annotations",
			setupMock: func() {
				mockECRClient.On("GetAuthorizationToken", mock.Anything, anyti, mock.Anything).Return(&ecr.GetAuthorizationTokenOutput{
					AuthorizationData: []types.AuthorizationData{
						{
							AuthorizationToken: &authorizationToken,
							ExpiresAt:          &expirationTime,
							ProxyEndpoint:      &proxyEndpoint,
						},
					},
				}, nil).Once()
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test-secret",
				},
			},
			expectedError: "",
			expectedPatches: patching.Operations{
				&patching.Operation{
					Op:    "add",
					Path:  "/metadata/annotations",
					Value: map[string]string{},
				},
				&patching.Operation{
					Op:    "add",
					Path:  "/metadata/annotations/" + patchFriendly(expiresAtAnnotationKey),
					Value: expirationTime.Format(time.RFC3339),
				},
				&patching.Operation{
					Op:    "add",
					Path:  "/metadata/annotations/" + patchFriendly(updatedAnnotationKey),
					Value: time.Now().Format(time.RFC3339),
				},
				&patching.Operation{
					Op:   "replace",
					Path: "/data",
					Value: map[string]string{
						".dockerconfigjson": base64.StdEncoding.EncodeToString(
							[]byte(fmt.Sprintf(
								`{"auths":{"https://proxy.example.com":{"username":"username","password":"password","auth":"%s"}}}`,
								authorizationToken,
							))),
					},
				},
			},
		},
		{
			name: "Successful injection - replace expiresAt and updated annotations",
			setupMock: func() {
				mockECRClient.On("GetAuthorizationToken", mock.Anything, anyti, mock.Anything).Return(&ecr.GetAuthorizationTokenOutput{
					AuthorizationData: []types.AuthorizationData{
						{
							AuthorizationToken: &authorizationToken,
							ExpiresAt:          &expirationTime,
							ProxyEndpoint:      &proxyEndpoint,
						},
					},
				}, nil).Once()
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "test-secret",
					Annotations: map[string]string{
						expiresAtAnnotationKey: expirationTime.Add(-12 * time.Hour).Format(time.RFC3339),
						updatedAnnotationKey:   time.Now().Add(-12 * time.Hour).Format(time.RFC3339),
					},
				},
			},
			expectedError: "",
			expectedPatches: patching.Operations{
				&patching.Operation{
					Op:    "replace",
					Path:  "/metadata/annotations/" + patchFriendly(expiresAtAnnotationKey),
					Value: expirationTime.Format(time.RFC3339),
				},
				&patching.Operation{
					Op:    "replace",
					Path:  "/metadata/annotations/" + patchFriendly(updatedAnnotationKey),
					Value: time.Now().Format(time.RFC3339),
				},
				&patching.Operation{
					Op:   "replace",
					Path: "/data",
					Value: map[string]string{
						".dockerconfigjson": base64.StdEncoding.EncodeToString(
							[]byte(fmt.Sprintf(
								`{"auths":{"https://proxy.example.com":{"username":"username","password":"password","auth":"%s"}}}`,
								authorizationToken,
							))),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			if tt.expectedError != "" {
				if tt.name == "GetAuthorizationToken fails" {
					assert.PanicsWithError(t, tt.expectedError, func() {
						_, _ = injector.Inject(tt.secret)
					})
				} else {
					_, err := injector.Inject(tt.secret)
					assert.EqualError(t, err, tt.expectedError)
				}
			} else {
				patches, err := injector.Inject(tt.secret)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedPatches, patches)
			}
			mockECRClient.AssertExpectations(t)
		})
	}
}

// TestRequestRefreshes tests the RequestRefreshes method of k8sCredentialRefreshRequester
func TestRequestRefreshes(t *testing.T) {
	tests := []struct {
		name            string
		namespaces      []corev1.Namespace
		secrets         map[string][]corev1.Secret
		force           bool
		expectedUpdates int
		expectedError   bool
	}{
		{
			name:            "No namespaces",
			namespaces:      []corev1.Namespace{},
			secrets:         map[string][]corev1.Secret{},
			force:           false,
			expectedUpdates: 0,
			expectedError:   false,
		},
		{
			name: "Namespace without secrets",
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "ns1", Labels: map[string]string{namespaceEnabledLabelKey: namespaceEnabledLabelValue}}},
			},
			secrets:         map[string][]corev1.Secret{},
			force:           false,
			expectedUpdates: 0,
			expectedError:   false,
		},
		{
			name: "Secrets without expiration annotations",
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "ns1", Labels: map[string]string{namespaceEnabledLabelKey: namespaceEnabledLabelValue}}},
			},
			secrets: map[string][]corev1.Secret{
				"ns1": {
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "secret1",
							Labels: map[string]string{
								managedLabelKey: managedLabelValue,
							},
						},
					},
				},
			},
			force:           false,
			expectedUpdates: 1,
			expectedError:   false,
		},
		{
			name: "Secrets with invalid expiration annotations",
			namespaces: []corev1.Namespace{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "ns1",
						Labels: map[string]string{
							namespaceEnabledLabelKey: namespaceEnabledLabelValue,
						},
					},
				},
			},
			secrets: map[string][]corev1.Secret{
				"ns1": {
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "secret1",
							Labels: map[string]string{
								managedLabelKey: managedLabelValue,
							},
							Annotations: map[string]string{
								expiresAtAnnotationKey: "invalid",
							},
						},
					},
				},
			},
			force:           false,
			expectedUpdates: 0,
			expectedError:   true,
		},
		{
			name: "Secrets due for refresh",
			namespaces: []corev1.Namespace{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "ns1",
						Labels: map[string]string{
							namespaceEnabledLabelKey: namespaceEnabledLabelValue,
						},
					},
				},
			},
			secrets: map[string][]corev1.Secret{
				"ns1": {
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "secret1",
							Labels: map[string]string{
								managedLabelKey: managedLabelValue,
							},
							Annotations: map[string]string{
								expiresAtAnnotationKey: time.Now().Add(5 * time.Hour).Format(time.RFC3339),
							},
						},
					},
				},
			},
			force:           false,
			expectedUpdates: 1,
			expectedError:   false,
		},
		{
			name: "Secrets not due for refresh",
			namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{
					Name: "ns1", Labels: map[string]string{namespaceEnabledLabelKey: namespaceEnabledLabelValue}}},
			},
			secrets: map[string][]corev1.Secret{
				"ns1": {
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "secret1",
							Labels: map[string]string{
								managedLabelKey: managedLabelValue,
							},
							Annotations: map[string]string{
								expiresAtAnnotationKey: time.Now().Add(7 * time.Hour).Format(time.RFC3339),
							},
						},
					},
				},
			},
			force:           false,
			expectedUpdates: 0,
			expectedError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()

			// Create namespaces and secrets in the fake clientset
			for _, ns := range tt.namespaces {
				_, err := clientset.CoreV1().Namespaces().Create(context.TODO(), &ns, metav1.CreateOptions{})
				if err != nil {
					t.Fatalf("error creating namespace: %v", err)
				}
				for _, secret := range tt.secrets[ns.Name] {
					_, err := clientset.CoreV1().Secrets(ns.Name).Create(context.TODO(), &secret, metav1.CreateOptions{})
					if err != nil {
						t.Fatalf("error creating secret: %v", err)
					}
				}
			}

			l := log.New(io.Discard, "", 0)
			kcr := NewK8sCredentialRefreshRequester(clientset, loggers.NewLoggers(l, l, l))

			err := kcr.RequestRefreshes(tt.force)
			if (err != nil) != tt.expectedError {
				t.Errorf("RequestRefreshes() error = %v, expectedError %v", err, tt.expectedError)
			}

			// Verify that the correct number of secrets were updated
			updatedCount := 0
			for _, ns := range tt.namespaces {
				secrets, err := clientset.CoreV1().Secrets(ns.Name).List(context.TODO(), metav1.ListOptions{})
				if err != nil {
					t.Fatalf("error listing secrets: %v", err)
				}

				for _, secret := range secrets.Items {
					if _, ok := secret.Annotations[markForUpdateAnnotationKey]; ok {
						updatedCount++
					}
				}
			}

			if updatedCount != tt.expectedUpdates {
				t.Errorf("expected %d secrets to be updated, but got %d", tt.expectedUpdates, updatedCount)
			}
		})
	}
}
