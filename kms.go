package secretsmanager

import (
	"context"
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// EncryptValue uses AWS KMS to encrypt a plaintext string.
// It returns a base64-encoded ciphertext.
func EncryptValue(ctx context.Context, client KMSClient, keyID, plaintext string) (string, error) {
	input := &kms.EncryptInput{
		KeyId:     &keyID,
		Plaintext: []byte(plaintext),
	}
	result, err := client.Encrypt(ctx, input)
	if err != nil {
		return "", err
	}
	// Encode the ciphertext in base64.
	return base64.StdEncoding.EncodeToString(result.CiphertextBlob), nil
}

// DecryptValue uses AWS KMS to decrypt a base64-encoded ciphertext.
// It returns the plaintext string.
func DecryptValue(ctx context.Context, client KMSClient, ciphertextB64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	input := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
	}
	result, err := client.Decrypt(ctx, input)
	if err != nil {
		return "", err
	}
	return string(result.Plaintext), nil
}
