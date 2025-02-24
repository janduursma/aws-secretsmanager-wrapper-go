// Package secretsmanager provides a wrapper for AWS Secrets Manager.
// It retrieves a JSON-encoded dictionary of secrets, caches individual key–value pairs
// (with each value encrypted via AWS KMS), and supports live secret rotation via a watcher.
// Built-in retry logic and error handling ensure robust secret retrieval, while a unified API
// abstracts away provider-specific details.
package secretsmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	logger "github.com/janduursma/zap-logger-wrapper"
)

// defaultCacheTTL is the default time-to-live for cached secrets.
const defaultCacheTTL = 10 * time.Minute

// Define interfaces for the AWS clients to inject mocks.

// Client defines the subset of methods needed from the AWS Secrets Manager client.
type Client interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// KMSClient defines the subset of methods needed from the AWS KMS client.
type KMSClient interface {
	Encrypt(ctx context.Context, input *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, input *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// SecretsManager is a wrapper around AWS Secrets Manager.
type SecretsManager struct {
	region     string
	secretName string
	kmsKeyID   string

	log *logger.Logger
	ctx context.Context

	secretsManagerClient Client
	kmsClient            KMSClient

	// Retry settings.
	maxAttempts  int
	initialDelay time.Duration
	maxDelay     time.Duration

	// Local cache: maps individual keys to their encrypted values and fetch time.
	cache     map[string]cachedSecret
	cacheTTL  time.Duration
	cacheLock sync.RWMutex
}

// cachedSecret holds an encrypted value and the time it was fetched.
type cachedSecret struct {
	encryptedValue string
	fetchedAt      time.Time
}

// Option defines a functional option for configuring SecretsManager.
type Option func(manager *SecretsManager)

// WithCacheTTL allows a custom cache TTL to be set.
func WithCacheTTL(ttl time.Duration) Option {
	return func(s *SecretsManager) {
		s.cacheTTL = ttl
	}
}

// WithSecretsManagerClient allows overriding the default Secrets Manager client for testing purposes.
func WithSecretsManagerClient(client Client) Option {
	return func(s *SecretsManager) {
		s.secretsManagerClient = client
	}
}

// WithKMSClient allows overriding the default KMS client for testing purposes.
func WithKMSClient(client KMSClient) Option {
	return func(s *SecretsManager) {
		s.kmsClient = client
	}
}

// NewSecretsManager creates a new SecretsManager.
func NewSecretsManager(region, secretName, kmsKeyID string, log *logger.Logger, opts ...Option) (*SecretsManager, error) {
	ctx := context.Background()

	// Load AWS config.
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.Error(ctx, "failed to load AWS config", err)
		return nil, err
	}

	// Create default AWS clients.
	defaultSecretsManagerClient := secretsmanager.NewFromConfig(cfg)
	defaultKMSClient := kms.NewFromConfig(cfg)

	secretsManager := &SecretsManager{
		region:               region,
		secretName:           secretName,
		kmsKeyID:             kmsKeyID,
		log:                  log,
		ctx:                  ctx,
		secretsManagerClient: defaultSecretsManagerClient,
		kmsClient:            defaultKMSClient,
		maxAttempts:          3,
		initialDelay:         500 * time.Millisecond,
		maxDelay:             5 * time.Second,
		cache:                make(map[string]cachedSecret),
		cacheTTL:             defaultCacheTTL,
	}

	// Apply options; if options are passed, they override the default.
	for _, opt := range opts {
		opt(secretsManager)
	}

	return secretsManager, nil
}

// retry retries the given operation with exponential backoff.
func (s *SecretsManager) retry(operation func() (map[string]string, error)) (map[string]string, error) {
	delay := s.initialDelay
	var lastErr error
	for i := 0; i < s.maxAttempts; i++ {
		result, err := operation()
		if err == nil {
			return result, nil
		}
		lastErr = err
		time.Sleep(delay)
		delay *= 2
		if delay > s.maxDelay {
			delay = s.maxDelay
		}
	}
	s.log.Error(s.ctx, fmt.Sprintf("operation failed after %d attempts", s.maxAttempts), lastErr)
	return nil, lastErr
}

// fetchSecrets retrieves the entire secret from AWS Secrets Manager.
func (s *SecretsManager) fetchSecrets() (map[string]string, error) {
	ctx := context.Background()
	operation := func() (map[string]string, error) {
		out, err := s.secretsManagerClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: &s.secretName,
		})
		if err != nil {
			return nil, err
		}
		if out.SecretString == nil || *out.SecretString == "" {
			errString := fmt.Sprintf("secret %q is nil or empty", s.secretName)
			err = errors.New(errString)
			s.log.Error(s.ctx, errString, err)
			return nil, err
		}
		var result map[string]string
		if err := json.Unmarshal([]byte(*out.SecretString), &result); err != nil {
			s.log.Error(s.ctx, "failed to unmarshal secret JSON", err)
			return nil, err
		}
		return result, nil
	}

	return s.retry(operation)
}

// Get retrieves the individual secret value for the given key.
// It refreshes the entire secret from AWS if the cache is expired.
func (s *SecretsManager) Get(key string) (string, error) {
	// Check local cache first.
	s.cacheLock.RLock()
	if cs, ok := s.cache[key]; ok && time.Since(cs.fetchedAt) < s.cacheTTL {
		s.cacheLock.RUnlock()
		// Decrypt the cached value.
		plaintext, err := DecryptValue(context.Background(), s.log, s.kmsClient, cs.encryptedValue)
		if err != nil {
			errString := fmt.Sprintf("failed to decrypt cached value for %s", key)
			err = errors.New(errString)
			s.log.Error(s.ctx, errString, err)
			return "", err
		}
		return plaintext, nil
	}
	s.cacheLock.RUnlock()

	// Cache miss: fetch the entire secret from AWS.
	secretsMap, err := s.fetchSecrets()
	if err != nil {
		s.log.Error(s.ctx, "failed to fetch secrets", err)
		return "", err
	}

	// Update cache for each key.
	s.cacheLock.Lock()
	defer s.cacheLock.Unlock()
	for k, v := range secretsMap {
		// Encrypt the value using KMS.
		enc, err := EncryptValue(context.Background(), s.log, s.kmsClient, s.kmsKeyID, v)
		if err != nil {
			s.log.Error(s.ctx, fmt.Sprintf("failed to encrypt secret %s", k), err)
			return "", err
		}
		s.cache[k] = cachedSecret{
			encryptedValue: enc,
			fetchedAt:      time.Now(),
		}
	}

	// Retrieve the requested key.
	cs, ok := s.cache[key]
	if !ok {
		errString := fmt.Sprintf("%s: secret not found", key)
		err = errors.New(errString)
		s.log.Error(s.ctx, errString, err)
		return "", err
	}
	plaintext, err := DecryptValue(context.Background(), s.log, s.kmsClient, cs.encryptedValue)
	if err != nil {
		s.log.Error(s.ctx, fmt.Sprintf("failed to decrypt secret %s", key), err)
		return "", err
	}
	return plaintext, nil
}

// Watch starts a background goroutine to poll for changes in the entire secret
// and calls the callback if the value for the given key changes.
func (s *SecretsManager) Watch(ctx context.Context, key string, interval time.Duration, callback func(newVal string)) {
	go func() {
		// Perform an initial fetch and set lastVal.
		lastVal, err := s.Get(key)
		if err != nil {
			s.log.Error(s.ctx, fmt.Sprintf("initial fetch failed for key %s", key), err)
			return
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				val, err := s.Get(key)
				if err != nil {
					s.log.Error(s.ctx, fmt.Sprintf("watch error for key %s", key), err)
					continue
				}
				if val != lastVal {
					lastVal = val
					callback(val)
				}
			}
		}
	}()
}
