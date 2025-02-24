package secretsmanager_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	awsSecretsManager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretsmanagerWrapper "github.com/janduursma/aws-secretsmanager-wrapper-go"
	logger "github.com/janduursma/zap-logger-wrapper"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// --- MOCKS ---

// mockSecretsManagerClient simulates a Secrets Manager client.
type mockSecretsManagerClient struct {
	// secretValue holds the current JSON string of the secret.
	secretValue atomic.Value
	// callCount tracks how many times GetSecretValue is called.
	callCount int32
	// err can simulate errors.
	err error
}

// GetSecretValue simulates the AWS SDK GetSecretValue method.
func (m *mockSecretsManagerClient) GetSecretValue(_ context.Context, _ *awsSecretsManager.GetSecretValueInput, _ ...func(*awsSecretsManager.Options)) (*awsSecretsManager.GetSecretValueOutput, error) {
	atomic.AddInt32(&m.callCount, 1)
	if m.err != nil {
		return nil, m.err
	}
	val := m.secretValue.Load().(string)
	return &awsSecretsManager.GetSecretValueOutput{
		SecretString: aws.String(val),
	}, nil
}

// mockKMSClient simulates a KMS client that does no real encryption or decryption.
type mockKMSClient struct{}

func (m *mockKMSClient) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	// Simulate encryption by returning the plaintext unchanged.
	return &kms.EncryptOutput{CiphertextBlob: input.Plaintext}, nil
}

func (m *mockKMSClient) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	// Simulate decryption by returning the ciphertext unchanged.
	return &kms.DecryptOutput{Plaintext: input.CiphertextBlob}, nil
}

// mockKMSClientDecryptFailure simulates a KMS client that fails on decryption.
type mockKMSClientDecryptFailure struct{}

func (m *mockKMSClientDecryptFailure) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	return &kms.EncryptOutput{CiphertextBlob: input.Plaintext}, nil
}

func (m *mockKMSClientDecryptFailure) Decrypt(_ context.Context, _ *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	return nil, fmt.Errorf("simulated decryption error")
}

// mockKMSClientEncryptFailure simulates a KMS client that fails on encryption.
type mockKMSClientEncryptFailure struct{}

func (m *mockKMSClientEncryptFailure) Encrypt(_ context.Context, _ *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	return nil, fmt.Errorf("simulated encryption error")
}

func (m *mockKMSClientEncryptFailure) Decrypt(_ context.Context, _ *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	// Not needed for this test.
	return nil, nil
}

// newSecretsManagerForTest creates a SecretsManager using the provided mock clients
// and a custom cache TTL.
func newSecretsManagerForTest(t *testing.T, sm secretsmanagerWrapper.Client, kms secretsmanagerWrapper.KMSClient, cacheTTL time.Duration) *secretsmanagerWrapper.SecretsManager {
	// Define a trace function that returns a fake trace ID.
	traceFn := func(_ context.Context) string { return "fake-trace-id" }

	// Create a logger
	l, err := logger.New("testSecretsManager", traceFn, zap.InfoLevel)
	if err != nil {
		log.Fatalf("failed to create logger: %v", err)
	}

	// Create the SecretsManager
	secretsManager, err := secretsmanagerWrapper.NewSecretsManager("us-test-1", "test-secret", "test-kms-key", l, secretsmanagerWrapper.WithSecretsManagerClient(sm), secretsmanagerWrapper.WithKMSClient(kms), secretsmanagerWrapper.WithCacheTTL(cacheTTL))
	require.NoError(t, err)

	return secretsManager
}

// --- TESTS ---

func TestSecretsManager_Get(t *testing.T) {
	// Simulate a secret JSON with multiple key/value pairs.
	initialData := map[string]string{
		"DB_PASSWORD": "initialPassword",
		"DB_USER":     "admin",
	}
	secretJSON, err := json.Marshal(initialData)
	require.NoError(t, err)

	// Set up mock Secrets Manager client.
	smMock := &mockSecretsManagerClient{}
	smMock.secretValue.Store(string(secretJSON))
	kmsMock := &mockKMSClient{}

	// Create the SecretsManager with a short cache TTL for testing.
	secretsManager := newSecretsManagerForTest(t, smMock, kmsMock, 100*time.Millisecond)

	// First call should fetch from the mock client and populate cache.
	val, err := secretsManager.Get("DB_PASSWORD")
	require.NoError(t, err)
	require.Equal(t, "initialPassword", val)
	require.Equal(t, int32(1), atomic.LoadInt32(&smMock.callCount))

	// Second call within TTL should return cached value (no additional call).
	val, err = secretsManager.Get("DB_PASSWORD")
	require.NoError(t, err)
	require.Equal(t, "initialPassword", val)
	require.Equal(t, int32(1), atomic.LoadInt32(&smMock.callCount))

	// Wait for the cache to expire.
	time.Sleep(150 * time.Millisecond)
	// Update the secret JSON to simulate secret rotation.
	updatedData := map[string]string{
		"DB_PASSWORD": "newPassword",
		"DB_USER":     "admin",
	}
	updatedJSON, err := json.Marshal(updatedData)
	require.NoError(t, err)
	smMock.secretValue.Store(string(updatedJSON))

	// Next Get should fetch the updated value.
	val, err = secretsManager.Get("DB_PASSWORD")
	require.NoError(t, err)
	require.Equal(t, "newPassword", val)
	require.Equal(t, int32(2), atomic.LoadInt32(&smMock.callCount))
}

func TestSecretsManager_Get_EncryptionError(t *testing.T) {
	// Test that if KMS decryption fails, Get returns an error.
	validData := map[string]string{
		"DB_PASSWORD": "validPassword",
	}
	secretJSON, err := json.Marshal(validData)
	require.NoError(t, err)

	smMock := &mockSecretsManagerClient{}
	smMock.secretValue.Store(string(secretJSON))
	// Use a KMS client that fails on encryption.
	failingKMS := &mockKMSClientEncryptFailure{}

	secretsManager := newSecretsManagerForTest(t, smMock, failingKMS, 50*time.Millisecond)

	_, err = secretsManager.Get("DB_PASSWORD")
	require.Error(t, err)
}

func TestSecretsManager_Get_DecryptionError(t *testing.T) {
	// Test that if KMS decryption fails, Get returns an error.
	validData := map[string]string{
		"DB_PASSWORD": "validPassword",
	}
	secretJSON, err := json.Marshal(validData)
	require.NoError(t, err)

	smMock := &mockSecretsManagerClient{}
	smMock.secretValue.Store(string(secretJSON))
	// Use a KMS client that fails on decryption.
	failingKMS := &mockKMSClientDecryptFailure{}

	secretsManager := newSecretsManagerForTest(t, smMock, failingKMS, 500*time.Millisecond)

	_, err = secretsManager.Get("DB_PASSWORD")
	require.Error(t, err)

	// Test if kms decryption fails when secret is cached.
	_, err = secretsManager.Get("DB_PASSWORD")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decrypt cached value for DB_PASSWORD")
}

func TestSecretsManager_Get_InvalidJSON(t *testing.T) {
	// Test that fetchSecrets returns an error on invalid JSON.
	invalidJSON := "this is not json"
	smMock := &mockSecretsManagerClient{}
	smMock.secretValue.Store(invalidJSON)
	kmsMock := &mockKMSClient{}

	secretsManager := newSecretsManagerForTest(t, smMock, kmsMock, 50*time.Millisecond)

	_, err := secretsManager.Get("DB_PASSWORD")
	require.Error(t, err)
}

func TestSecretsManager_Get_NilSecretString(t *testing.T) {
	// Test that fetchSecrets returns an error when SecretString is nil.
	smMock := &mockSecretsManagerClient{}
	smMock.secretValue.Store("") // Simulate nil or empty SecretString.
	kmsMock := &mockKMSClient{}

	secretsManager := newSecretsManagerForTest(t, smMock, kmsMock, 50*time.Millisecond)

	_, err := secretsManager.Get("DB_PASSWORD")
	require.Error(t, err)
}

func TestSecretsManager_RetryFailure(t *testing.T) {
	// Test that if the Secrets Manager client always returns an error, Get fails after retries.
	smMock := &mockSecretsManagerClient{err: fmt.Errorf("simulated SM error")}
	kmsMock := &mockKMSClient{}

	secretsManager := newSecretsManagerForTest(t, smMock, kmsMock, 50*time.Millisecond)

	_, err := secretsManager.Get("DB_PASSWORD")
	require.Error(t, err)
	require.Equal(t, int32(3), atomic.LoadInt32(&smMock.callCount))
}

func TestSecretsManager_Get_SecretNotFound(t *testing.T) {
	// Test that if the secret is not found, Get returns an error.
	validData := map[string]string{
		"DB_PASSWORD": "validPassword",
	}

	secretJSON, err := json.Marshal(validData)
	require.NoError(t, err)

	smMock := &mockSecretsManagerClient{}
	smMock.secretValue.Store(string(secretJSON)) // Simulate nil or empty SecretString.
	kmsMock := &mockKMSClient{}

	secretsManager := newSecretsManagerForTest(t, smMock, kmsMock, 50*time.Millisecond)

	_, err = secretsManager.Get("NON_EXISTENT_KEY")
	require.Error(t, err)
}

func TestSecretsManager_Watch(t *testing.T) {
	// Prepare an initial secret JSON.
	initialData := map[string]string{
		"DB_PASSWORD": "initialPassword",
	}
	initialJSON, err := json.Marshal(initialData)
	require.NoError(t, err)

	smMock := &mockSecretsManagerClient{}
	smMock.secretValue.Store(string(initialJSON))
	kmsMock := &mockKMSClient{}

	// Create the SecretsManager
	// Use a short cache TTL so updates are picked up quickly.
	secretsManager := newSecretsManagerForTest(t, smMock, kmsMock, 50*time.Millisecond)

	// Channel to capture callback values.
	callbackCh := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start watching for changes on "DB_PASSWORD" every 20ms.
	secretsManager.Watch(ctx, "DB_PASSWORD", 20*time.Millisecond, func(newVal string) {
		callbackCh <- newVal
	})

	// Wait a short time to allow the initial value to be polled.
	time.Sleep(200 * time.Millisecond)

	// Update the secret JSON to simulate rotation.
	updatedData := map[string]string{
		"DB_PASSWORD": "rotatedPassword",
	}
	updatedJSON, err := json.Marshal(updatedData)
	require.NoError(t, err)
	smMock.secretValue.Store(string(updatedJSON))

	// Wait for the watcher to detect the change.
	select {
	case newVal := <-callbackCh:
		require.Equal(t, "rotatedPassword", newVal)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for watcher callback")
	}
}

func TestDecryptValue_InvalidBase64(t *testing.T) {
	ctx := context.Background()

	traceFn := func(_ context.Context) string { return "test-trace-id" }
	l, err := logger.New("test", traceFn, zap.InfoLevel)
	require.NoError(t, err)

	kmsClient := &mockKMSClient{}

	// Pass an invalid base64 string so that decoding fails.
	invalidCiphertext := "not_base64"

	plaintext, err := secretsmanagerWrapper.DecryptValue(ctx, l, kmsClient, invalidCiphertext)
	require.Error(t, err)
	require.Empty(t, plaintext)
}
