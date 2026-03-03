# S3Proxy for k3s-argocd-cluster (forked from [Intrinsec](https://github.com/Intrinsec/s3proxy))

**S3Proxy** is a Docker image that enables transparent client-side encryption for S3 object traffic. The proxy intercepts PUT and GET requests and encrypts/decrypts object payloads with the AWS Amazon S3 Encryption Client for Go.

## Hard Fork Status

This repository is now a **hard fork** of `Intrinsec/s3proxy`.

- It is maintained independently.
- It does **not** aim to stay in sync with the original upstream.
- Future development, architecture, compatibility decisions, and release cadence are defined by this repository only.

Rationale:

- The origin has a severe [security issue](https://github.com/Intrinsec/s3proxy/issues/21), multiple outstanding PRs, and appeared unmaintained.
- To unblock real-world usage (including Longhorn backups to BackBlaze B2), this project moved to an independent code and release path.

PRs included:
- [Reduce RAM usage](https://github.com/Intrinsec/s3proxy/pull/28), from [vetal4444](https://github.com/vetal4444)
- [Fix security issue & code cleanup](https://github.com/Intrinsec/s3proxy/pull/32), from [ynsta](https://github.com/ynsta)

## Features

- **Automatic encryption** for all PUT requests before storage on S3
- **Transparent decryption** of GET requests when retrieving data from S3
- **Easy setup**: run the proxy and direct your HTTP requests through it.

## Usage (Docker)

```bash
docker run ghcr.io/k3s-argocd-cluster/s3proxy --rm -p 80:4433 -p 9001:9001 -e AWS_ACCESS_KEY_ID="XXX" -e AWS_SECRET_ACCESS_KEY="XXX" -e S3PROXY_KMS_STATIC_KEY="GENERATE_A_RANDOM_STRING" -e S3PROXY_HOST="s3.fr-par.scw.cloud"
```

## Usage (Kubernetes - Helm)

```bash
helm ugprade --install s3proxy oci://ghcr.io/k3s-argocd-cluster/s3proxy/charts/s3proxy
```

## Contribution

[CONTRIBUTING](CONTRIBUTING.md)

## Technical Details

### Architecture

S3Proxy acts as an intermediary, intercepting S3 PUT and GET requests to provide transparent encryption/decryption.

- **PUT Object Flow:**
  1. S3Proxy intercepts a PUT request.
  2. Cache entries on the target path and parent path are invalidated.
  3. The request body is encrypted by `amazon-s3-encryption-client-go/v4`.
  4. Envelope key operations are handled by a local static-key KMS implementation.
  5. Encrypted data and metadata are forwarded to the S3 provider.

- **GET Object Flow:**
  1. S3Proxy intercepts a GET request.
  2. The AWS encryption client fetches and decrypts object content transparently.
  3. Plaintext is returned to the caller.

- **FORWARD Flow:**
  1. Anything that wasn't identified a S3 GetObject or PutObject command will be forwarded without encryption
  2. If incoming request is either Put, Post, Patch or Delete purge any cached element for given path (and its parent)
  3. If caching was enabled, try to retrieve the cached data (Header, Body, StatusCode) for given path and method from cache
  4. If not cached yet or method is not applicable for caching or caching is not enabled, manipulate request (i.e. make use of configured credentials) & forward to S3 backend
  5. If caching was enabled & method is applicable for caching, store Header, Body & StatusCode for given path & method

Key components and their roles:
- `cmd/main.go`: The entry point of the application, responsible for parsing command-line flags, setting up logging (`logrus`), loading configuration (`koanf`), and starting the HTTP server.
- `internal/router`: Implements request interception/routing and middleware orchestration for object interception, forwarding, caching and request throttling.
- `internal/s3`: Provides a thin wrapper around the AWS S3 client (`github.com/aws/aws-sdk-go-v2/service/s3`) for seamless interaction with the S3 backend. It includes custom middleware to capture raw HTTP responses, which is crucial for robust error handling.
- `internal/encryption`: Integrates `github.com/aws/amazon-s3-encryption-client-go/v4` and a local static-key KMS client used for envelope key generation/decryption.
- `internal/caching`: Implements caching for repetitive GET and HEAD requests. Currently this is a very basic implementation using local memory only, may be extended to use Redis later on.

Multipart upload requests (`CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`) are always blocked for security reasons.

### KMS Static Key Guidance

- `S3PROXY_KMS_STATIC_KEY` is normalized to a 32-byte key (AES-256 strength) by the local static KMS client.
- Increasing the input string length does not increase effective cryptographic strength beyond 256 bits.
- For safety, prefer a high-entropy random 32-byte secret (base64 or hex encoded), store it in a proper secret manager, and rotate it with a defined process.
  Generate one with OpenSSL:
  ```bash
  openssl rand -base64 32
  ```
- Security gains mainly come from key lifecycle controls (generation, storage, rotation, access control, audit), not from trying to use a larger nominal key size.

### Main Libraries Used

- **Configuration:** [`github.com/knadh/koanf`](https://github.com/knadh/koanf) for flexible configuration loading from environment variables (e.g., `S3PROXY_HOST` maps to `s3proxy.host`).
- **Logging:** [`github.com/sirupsen/logrus`](https://github.com/sirupsen/logrus) for structured and configurable logging.
- **AWS SDK:** [`github.com/aws/aws-sdk-go-v2/service/s3`](https://github.com/aws/aws-sdk-go-v2/service/s3) for all interactions with the S3 backend.
- **Cryptography:** [`github.com/aws/amazon-s3-encryption-client-go/v4`](https://github.com/aws/amazon-s3-encryption-client-go) for client-side object encryption.
- **UUID Generation:** [`github.com/google/uuid`](https://github.com/google/uuid) for generating unique request identifiers.

### Metrics

S3Proxy exposes Prometheus metrics on the ops listener at:

- `GET /metrics`

Key metrics currently exported:

- `s3proxy_requests_processed_total{method,operation,status}`
  Counts processed requests by HTTP method, classified operation (`put_object`, `get_object`, `forward`, multipart operations), and response status.
- `s3proxy_files_uploaded_total`
  Counts successful intercepted object uploads (`PutObject` path).
- `s3proxy_files_downloaded_total`
  Counts successful intercepted object downloads (`GetObject` path).
- `s3proxy_upload_bytes_total`
  Total uploaded payload bytes processed by intercepted `PutObject`.
- `s3proxy_download_bytes_total`
  Total downloaded payload bytes processed by intercepted `GetObject`.
- `s3proxy_cache_hits_total`
  Number of cache hits served directly from cache middleware.
- `s3proxy_cache_misses_total`
  Number of cache lookups that did not find an element.
- `s3proxy_cache_stores_total`
  Number of responses stored in cache.
- `s3proxy_cache_invalidations_total`
  Number of cache invalidation operations triggered by mutating requests.
- `s3proxy_cache_elements_removed_total`
  Total number of cache elements actually removed during invalidation.
- `s3proxy_cache_entries`
  Current number of entries in cache.
- `s3proxy_cache_bytes`
  Estimated current size of cached bodies/headers in bytes.
- `s3proxy_memory_alloc_bytes`
  Go runtime currently allocated heap bytes (`runtime.MemStats.Alloc`).

Notes:

- With `--cache=memory`, cache hit/miss/store and cache size metrics are expected to move over time.
- With `--cache=none`, cache hit count should stay flat and cache size gauges should remain at `0` (the cache middleware still executes and can increase miss/store counters).

### Deployment (Helm Chart)

S3Proxy can be easily deployed on Kubernetes using its official Helm chart located at `charts/s3proxy`. The chart provides a flexible way to configure and manage S3Proxy instances.

Key configurable parameters via `values.yaml` include:
- `replicaCount`: Number of S3Proxy instances to run.
- `image`: Docker image repository and tag for S3Proxy.
- `args`: Command-line configuration with flag toggles:
  - `args.logLevel` for `--level`
  - `args.noTLS` for `--no-tls`
  - `args.noTagging` for `--no-tagging`
  - `args.cache` for `--cache=<type>`
  - `args.extra` to append custom args
  - `args.rawOverride` to fully override generated args
- `cert`: Configuration for CertManager integration to automatically provision TLS certificates.
- `config`: Settings for the S3 backend, including `host`, `throttling` (maximum requests per second), `accessKey`, `secretKey`, and `kmsStaticKey`.
- `service`: Kubernetes Service configuration (defaults to `ClusterIP` on port `4433`).
- `ingress`: Optional Ingress configuration for external access.
- `resources`: CPU and memory limits and requests for the S3Proxy pods.
- `livenessProbe` and `readinessProbe`: Health check configurations pointing to `/healthz` and `/readyz` on the ops port.

## Breaking Change

This release is not backward compatible with objects encrypted using the previous custom DEK metadata format.
- `autoscaling`: Horizontal Pod Autoscaler (HPA) settings for automatic scaling based on CPU and memory utilization.

The Helm chart deploys S3Proxy as a Kubernetes `Deployment` and exposes it via a `Service`, ensuring high availability and scalability.
