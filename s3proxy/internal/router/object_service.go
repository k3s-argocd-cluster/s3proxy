package router

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type encryptedClient interface {
	GetObject(ctx context.Context, bucket, key, versionID, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, bucket, key, tags, contentType, objectLockLegalHoldStatus, objectLockMode, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string, objectLockRetainUntilDate time.Time, metadata map[string]string, body io.Reader, tagging bool) (*s3.PutObjectOutput, error)
}

type objectService struct {
	client encryptedClient
}

type getObjectInput struct {
	bucket               string
	key                  string
	versionID            string
	sseCustomerAlgorithm string
	sseCustomerKey       string
	sseCustomerKeyMD5    string
}

type putObjectInput struct {
	bucket                    string
	key                       string
	body                      io.Reader
	tags                      string
	contentType               string
	metadata                  map[string]string
	objectLockLegalHoldStatus string
	objectLockMode            string
	objectLockRetainUntilDate time.Time
	sseCustomerAlgorithm      string
	sseCustomerKey            string
	sseCustomerKeyMD5         string
	tagging                   bool
}

type getObjectResult struct {
	headers http.Header
	body    io.ReadCloser
}

type putObjectResult struct {
	headers http.Header
}

func newObjectService(client encryptedClient) objectService {
	return objectService{client: client}
}

func (s objectService) get(ctx context.Context, input getObjectInput) (getObjectResult, error) {
	output, err := s.client.GetObject(
		ctx,
		input.bucket,
		input.key,
		input.versionID,
		input.sseCustomerAlgorithm,
		input.sseCustomerKey,
		input.sseCustomerKeyMD5,
	)
	if err != nil {
		return getObjectResult{}, err
	}

	headers := make(http.Header)
	setGetObjectHeaders(headers, output)

	return getObjectResult{headers: headers, body: output.Body}, nil
}

func (s objectService) put(ctx context.Context, input putObjectInput) (putObjectResult, error) {
	output, err := s.client.PutObject(
		ctx,
		input.bucket,
		input.key,
		input.tags,
		input.contentType,
		input.objectLockLegalHoldStatus,
		input.objectLockMode,
		input.sseCustomerAlgorithm,
		input.sseCustomerKey,
		input.sseCustomerKeyMD5,
		input.objectLockRetainUntilDate,
		input.metadata,
		input.body,
		input.tagging,
	)
	if err != nil {
		return putObjectResult{}, err
	}

	headers := make(http.Header)
	setPutObjectHeaders(headers, output)

	return putObjectResult{headers: headers}, nil
}

func setHeaderIfNonEmpty(h http.Header, key string, val *string) {
	if val != nil {
		v := strings.TrimSpace(*val)
		if v != "" {
			h.Set(key, v)
		}
	}
}

func setPutObjectHeaders(headers http.Header, output *s3.PutObjectOutput) {
	if output.ETag != nil {
		headers.Set("ETag", strings.Trim(*output.ETag, "\""))
	}
	setHeaderIfNonEmpty(headers, "x-amz-version-id", output.VersionId)
	setHeaderIfNonEmpty(headers, "x-amz-expiration", output.Expiration)
	setHeaderIfNonEmpty(headers, "x-amz-checksum-crc32", output.ChecksumCRC32)
	setHeaderIfNonEmpty(headers, "x-amz-checksum-crc32c", output.ChecksumCRC32C)
	setHeaderIfNonEmpty(headers, "x-amz-checksum-sha1", output.ChecksumSHA1)
	setHeaderIfNonEmpty(headers, "x-amz-checksum-sha256", output.ChecksumSHA256)
	setHeaderIfNonEmpty(headers, "x-amz-server-side-encryption-customer-algorithm", output.SSECustomerAlgorithm)
	setHeaderIfNonEmpty(headers, "x-amz-server-side-encryption-customer-key-MD5", output.SSECustomerKeyMD5)
	setHeaderIfNonEmpty(headers, "x-amz-server-side-encryption-aws-kms-key-id", output.SSEKMSKeyId)
	setHeaderIfNonEmpty(headers, "x-amz-server-side-encryption-context", output.SSEKMSEncryptionContext)
	if output.ServerSideEncryption != "" {
		headers.Set("x-amz-server-side-encryption", string(output.ServerSideEncryption))
	}
}

func setGetObjectHeaders(headers http.Header, output *s3.GetObjectOutput) {
	if output.ETag != nil {
		headers.Set("ETag", strings.Trim(*output.ETag, "\""))
	}
	setHeaderIfNonEmpty(headers, "x-amz-expiration", output.Expiration)
	setHeaderIfNonEmpty(headers, "x-amz-checksum-crc32", output.ChecksumCRC32)
	setHeaderIfNonEmpty(headers, "x-amz-checksum-crc32c", output.ChecksumCRC32C)
	setHeaderIfNonEmpty(headers, "x-amz-checksum-sha1", output.ChecksumSHA1)
	setHeaderIfNonEmpty(headers, "x-amz-checksum-sha256", output.ChecksumSHA256)
	setHeaderIfNonEmpty(headers, "x-amz-server-side-encryption-customer-algorithm", output.SSECustomerAlgorithm)
	setHeaderIfNonEmpty(headers, "x-amz-server-side-encryption-customer-key-MD5", output.SSECustomerKeyMD5)
	setHeaderIfNonEmpty(headers, "x-amz-server-side-encryption-aws-kms-key-id", output.SSEKMSKeyId)
	if output.ServerSideEncryption != "" {
		headers.Set("x-amz-server-side-encryption", string(output.ServerSideEncryption))
	}
}
