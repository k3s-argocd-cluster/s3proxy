package encryption

import (
	"context"
	"fmt"
	"io"
	"time"

	s3crypto "github.com/aws/amazon-s3-encryption-client-go/v4/client"
	"github.com/aws/amazon-s3-encryption-client-go/v4/materials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	defaultKeyID = "s3proxy-static-kms-key"
)

// Client wraps the AWS S3 encryption client with the same operational surface used by the router.
type Client struct {
	encryptionClient *s3crypto.S3EncryptionClientV4
}

func New(baseS3Client *awss3.Client, staticKey string) (*Client, error) {
	if baseS3Client == nil {
		return nil, fmt.Errorf("base S3 client is nil")
	}

	kmsClient := NewStaticKMSClient(staticKey)
	keyring := materials.NewKmsKeyring(kmsClient, defaultKeyID)
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		return nil, fmt.Errorf("creating cryptographic materials manager: %w", err)
	}

	encryptionClient, err := s3crypto.New(baseS3Client, cmm)
	if err != nil {
		return nil, fmt.Errorf("creating s3 encryption client: %w", err)
	}

	return &Client{encryptionClient: encryptionClient}, nil
}

// GetObject returns plaintext object contents while enforcing an encryption context binding to bucket and key.
func (c Client) GetObject(ctx context.Context, bucket, key, versionID, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string) (*awss3.GetObjectOutput, error) {
	getObjectInput := &awss3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}
	if versionID != "" {
		getObjectInput.VersionId = &versionID
	}
	if sseCustomerAlgorithm != "" {
		getObjectInput.SSECustomerAlgorithm = &sseCustomerAlgorithm
	}
	if sseCustomerKey != "" {
		getObjectInput.SSECustomerKey = &sseCustomerKey
	}
	if sseCustomerKeyMD5 != "" {
		getObjectInput.SSECustomerKeyMD5 = &sseCustomerKeyMD5
	}

	return c.encryptionClient.GetObject(withEncryptionContext(ctx, bucket, key), getObjectInput)
}

// PutObject writes plaintext object contents and encrypts transparently using the encryption client.
func (c Client) PutObject(ctx context.Context, bucket, key, tags, contentType, objectLockLegalHoldStatus, objectLockMode, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string, objectLockRetainUntilDate time.Time, metadata map[string]string, body io.Reader, tagging bool) (*awss3.PutObjectOutput, error) {
	if contentType == "" {
		contentType = "binary/octet-stream"
	}

	putObjectInput := &awss3.PutObjectInput{
		Bucket:                    &bucket,
		Key:                       &key,
		Body:                      body,
		Metadata:                  metadata,
		ContentType:               &contentType,
		ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatus(objectLockLegalHoldStatus),
	}
	if sseCustomerAlgorithm != "" {
		putObjectInput.SSECustomerAlgorithm = &sseCustomerAlgorithm
	}
	if sseCustomerKey != "" {
		putObjectInput.SSECustomerKey = &sseCustomerKey
	}
	if sseCustomerKeyMD5 != "" {
		putObjectInput.SSECustomerKeyMD5 = &sseCustomerKeyMD5
	}
	if tagging {
		putObjectInput.Tagging = &tags
	}

	if objectLockMode != "" && !objectLockRetainUntilDate.IsZero() {
		putObjectInput.ObjectLockMode = types.ObjectLockMode(objectLockMode)
		putObjectInput.ObjectLockRetainUntilDate = &objectLockRetainUntilDate
	}

	return c.encryptionClient.PutObject(withEncryptionContext(ctx, bucket, key), putObjectInput)
}

func withEncryptionContext(ctx context.Context, bucket, key string) context.Context {
	encryptionContext := map[string]string{
		"bucket": bucket,
		"key":    key,
	}
	//nolint:staticcheck // Required by the AWS encryption client API: key type is a string constant.
	return context.WithValue(ctx, s3crypto.EncryptionContext, encryptionContext)
}
