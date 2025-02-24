# aws-secretsmanager-wrapper-go

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/janduursma/aws-secretsmanager-wrapper-go)](https://goreportcard.com/report/github.com/janduursma/aws-secretsmanager-wrapper-go)
[![semantic-release](https://img.shields.io/badge/semantic--release-ready-brightgreen)](https://github.com/go-semantic-release/go-semantic-release)
[![codecov](https://codecov.io/gh/janduursma/aws-secretsmanager-wrapper-go/graph/badge.svg?token=LBQGOP14WJ)](https://codecov.io/gh/janduursma/aws-secretsmanager-wrapper-go)

The AWS Secrets Manager Wrapper is designed to simplify secrets management in AWS. It wraps the official AWS Secrets Manager caching library and extends its functionality with:

- **Live Secret Rotation (Watcher):** Provides a watcher that polls for secret changes (e.g. after a key rotation) and triggers callbacks to update configuration dynamically.
- **Encryption in Cache via AWS KMS:** Cached secret values are encrypted using AWS KMS so that even if the cache is compromised, the secrets remain protected.
- **Caching of Secret Key–Value Pairs:** Fetches a secret from AWS Secrets Manager (one secret can contain multiple keys) and caches each individual key value securely.
- **Built-in Retry Logic:** Automatically retries secret retrieval with exponential backoff for network or transient errors.


This package is intended for production use and local development. It is especially useful for microservices that need to securely fetch and manage secrets without tying the application code directly to AWS SDK calls.

---

## Features

- **Unified API:** Call `Get("MY_SECRET_KEY")` to retrieve an individual secret value, regardless of the underlying AWS configuration.
- **Efficient Retrieval:** Fetches the entire secret in one network call and caches each key/value pair.
- **Secure Caching:** Uses AWS KMS to encrypt cached secret values.
- **Automatic Retry:** Retries transient errors with exponential backoff.
- **Live Rotation:** Watch a secret for changes and trigger a callback when a secret is rotated.

---

## Installation

To install the package, use:

```bash
go get github.com/janduursma/aws-secretsmanager-wrapper-go
```

Then import it in your Go code:

```go
import secretsmanager "github.com/janduursma/aws-secretsmanager-wrapper-go"
```

---

## Configuration

The package requires several AWS-specific environment variables to be set, or to be [configured](https://docs.aws.amazon.com/cli/latest/reference/configure/):

- **AWS_REGION:** The AWS region where your secret is stored.
- **AWS_SECRET_ID:** The AWS access key part of your credentials.
- **AWS_SECRET_ACCESS_KEY:** The AWS secret access key part of your credentials.

This secrets manager wrapper uses functional options to allow you to customize its behavior. By default, it is configured as follows:
- **Cache TTL:** 10 minutes  
  The default cacheTTL is set to `10 minutes`. You can override this using the `WithCacheTTL` option.


---

## Usage

Below is a simple example that demonstrates how to use the package in a service:

```go
package main

import (
	"log"
	"time"
	
	secretsmanager "github.com/janduursma/aws-secretsmanager-wrapper-go"
)

func main() {
	// Create AWS Secrets Manager with custom cacheTTL of 30 minutes.
	secretManager, err := secretsmanager.NewSecretsManager("us-west-2", "my-secret-id", "my-kms-key-id", secretsmanager.WithCacheTTL(30*time.Minute))
	if err != nil {
		log.Fatalf("failed to create AWS Secrets Manager: %v", err)
	}

	// Now use the secrets manager:
	_, err = secretManager.Get("DB_PASSWORD")
}
```

---

## Running Tests
```sh
go test ./...
```

---

## License
- [MIT License](LICENSE)
