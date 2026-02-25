/*
Copyright (c) Edgeless Systems GmbH
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/k3s-argocd-cluster/s3proxy/internal/config"
	crypto "github.com/k3s-argocd-cluster/s3proxy/internal/crypto"
	logger "github.com/sirupsen/logrus"
)

var (
	// dekTag is the name of the header that holds the encrypted data encryption key for the attached object. Presence of the key implies the object needs to be decrypted.
	// Use lowercase only, as AWS automatically lowercases all metadata keys.
	dekTag = config.GetDekTagName()
)

// object bundles data to implement http.Handler methods that use data from incoming requests.
type object struct {
	kek                       [32]byte
	client                    s3Client
	key                       string
	bucket                    string
	data                      []byte
	query                     url.Values
	tags                      string
	contentType               string
	metadata                  map[string]string
	objectLockLegalHoldStatus string
	objectLockMode            string
	objectLockRetainUntilDate time.Time
	sseCustomerAlgorithm      string
	sseCustomerKey            string
	sseCustomerKeyMD5         string
	versionID                 string
	log                       *logger.Logger
}

func setHeaderIfNonEmpty(h http.Header, key string, val *string) {
	if val != nil {
		v := strings.TrimSpace(*val)
		if v != "" {
			h.Set(key, v)
		}
	}
}

// get is a http.HandlerFunc that implements the GET method for objects.
func (o object) get(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()

	o.log.WithField("requestID", requestID).WithField("key", o.key).WithField("bucket", o.bucket).Debug("getObject")

	output, err := o.client.GetObject(context.WithoutCancel(r.Context()), o.bucket, o.key, o.versionID, o.sseCustomerAlgorithm, o.sseCustomerKey, o.sseCustomerKeyMD5)

	if err != nil {
		// log with Info as it might be expected behavior (e.g. object not found).
		o.log.WithField("requestID", requestID).WithField("error", err).Error("GetObject sending request to S3")
		handleGetObjectError(w, err, requestID, o.log)
		return
	}

	setGetObjectHeaders(w, output)

	plaintext := func() (result []byte) {
		var body []byte
		if output.ContentLength == nil {
			// fallback on io.ReadAll if ContentLength is unknown
			body, err = io.ReadAll(output.Body)
			if err != nil {
				o.log.WithField("requestID", requestID).WithField("error", err).Error("GetObject reading S3 response")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return nil
			}
		} else {
			n := int(*output.ContentLength)
			// Preallocate the buffer from Content-Length and fill it with io.ReadFull.
			// This avoids the incremental growth and extra copies that io.ReadAll incurs
			// when the final size is unknown, which can blow up RAM on large payloads.
			// If Content-Length is missing or bogus we fall back to ReadAll below.
			body = make([]byte, n)
			if _, err := io.ReadFull(output.Body, body); err != nil {
				o.log.WithField("requestID", requestID).WithField("error", err).Error("GetObject reading S3 response")
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return nil
			}
		}

		result = body
		rawEncryptedDEK, ok := output.Metadata[dekTag]
		if ok {
			encryptedDEK, err := hex.DecodeString(rawEncryptedDEK)
			if err != nil {
				o.log.WithField("requestID", requestID).WithField("error", err).Error("GetObject decoding DEK")
				http.Error(w, "failed to decode encryption key", http.StatusInternalServerError)
				return nil
			}

			result, err = crypto.Decrypt(body, encryptedDEK, o.kek)
			if err != nil {
				o.log.WithField("requestID", requestID).WithField("error", err).Error("GetObject decrypting response")
				http.Error(w, "failed to decrypt object", http.StatusInternalServerError)
				return nil
			}
		} else {
			o.log.Warn("WTF ?!") // <-- TODO: Do we really want this?!
		}

		return result
	}()

	defer output.Body.Close()

	if plaintext == nil {
		return
	}

	select {
	case <-r.Context().Done():
		o.log.WithField("requestID", requestID).Info("Request was canceled by client")
		return
	default:
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(plaintext); err != nil {
			if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
				o.log.WithField("requestID", requestID).Info("Client closed the connection")
			} else {
				o.log.WithField("requestID", requestID).WithField("error", err).Error("GetObject sending response")
			}
		}
	}
}

// put is a http.HandlerFunc that implements the PUT method for objects.
func (o *object) put(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()
	o.log.WithField("requestID", requestID).WithField("key", o.key).WithField("bucket", o.bucket).Debug("putObject")

	ciphertext, encryptedDEK, err := crypto.Encrypt(o.data, o.kek)
	if err != nil {
		o.log.WithField("requestID", requestID).WithField("error", err).Error("PutObject")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// as data was just encrypted, the raw data is not required any more
	// so remove the reference and let the GC do its job
	o.data = nil
	o.metadata[dekTag] = hex.EncodeToString(encryptedDEK)

	output, err := o.client.PutObject(context.WithoutCancel(r.Context()), o.bucket, o.key, o.tags, o.contentType, o.objectLockLegalHoldStatus, o.objectLockMode, o.sseCustomerAlgorithm, o.sseCustomerKey, o.sseCustomerKeyMD5, o.objectLockRetainUntilDate, o.metadata, ciphertext)
	if err != nil {
		var httpResponseErr *awshttp.ResponseError
		if errors.As(err, &httpResponseErr) {
			code := httpResponseErr.HTTPStatusCode()
			o.log.WithField("requestID", requestID).WithField("code", code).WithField("httpResponseErr", httpResponseErr).Error("PutObject sending request to S3")
			http.Error(w, err.Error(), code)
			return
		}

		o.log.WithField("requestID", requestID).WithField("error", err).Error("PutObject sending request to S3")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	setPutObjectHeaders(w, output)

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(nil); err != nil {
		o.log.WithField("requestID", requestID).WithField("error", err).Error("PutObject sending response")
	}
}

func setPutObjectHeaders(w http.ResponseWriter, output *s3.PutObjectOutput) {
	if output.ETag != nil {
		w.Header().Set("ETag", strings.Trim(*output.ETag, "\""))
	}
	setHeaderIfNonEmpty(w.Header(), "x-amz-version-id", output.VersionId)
	setHeaderIfNonEmpty(w.Header(), "x-amz-expiration", output.Expiration)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-crc32", output.ChecksumCRC32)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-crc32c", output.ChecksumCRC32C)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-sha1", output.ChecksumSHA1)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-sha256", output.ChecksumSHA256)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-customer-algorithm", output.SSECustomerAlgorithm)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-customer-key-MD5", output.SSECustomerKeyMD5)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-aws-kms-key-id", output.SSEKMSKeyId)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-context", output.SSEKMSEncryptionContext)
	if output.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(output.ServerSideEncryption))
	}
}

func handleGetObjectError(w http.ResponseWriter, err error, requestID string, log *logger.Logger) {
	log.WithField("requestID", requestID).WithField("error", err).Error("GetObject sending request to S3")
	var httpResponseErr *awshttp.ResponseError
	if errors.As(err, &httpResponseErr) {
		code := httpResponseErr.HTTPStatusCode()
		log.WithField("requestID", requestID).WithField("code", code).WithField("httpResponseErr", httpResponseErr).Error("GetObject sending request to S3 (awshttp.ResponseError)")
		http.Error(w, err.Error(), code)
		for key := range httpResponseErr.Response.Header {
			w.Header().Set(key, httpResponseErr.Response.Header.Get(key))
		}
	}

	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func setGetObjectHeaders(w http.ResponseWriter, output *s3.GetObjectOutput) {
	if output.ETag != nil {
		w.Header().Set("ETag", strings.Trim(*output.ETag, "\""))
	}
	setHeaderIfNonEmpty(w.Header(), "x-amz-expiration", output.Expiration)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-crc32", output.ChecksumCRC32)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-crc32c", output.ChecksumCRC32C)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-sha1", output.ChecksumSHA1)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-sha256", output.ChecksumSHA256)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-customer-algorithm", output.SSECustomerAlgorithm)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-customer-key-MD5", output.SSECustomerKeyMD5)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-aws-kms-key-id", output.SSEKMSKeyId)
	if output.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(output.ServerSideEncryption))
	}
}

type s3Client interface {
	GetObject(ctx context.Context, bucket, key, versionID, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, bucket, key, tags, contentType, objectLockLegalHoldStatus, objectLockMode, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string, objectLockRetainUntilDate time.Time, metadata map[string]string, body []byte) (*s3.PutObjectOutput, error)
}
