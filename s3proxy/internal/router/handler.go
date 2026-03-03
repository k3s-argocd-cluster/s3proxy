/*
Copyright (c) Edgeless Systems GmbH
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/google/uuid"
	"github.com/k3s-argocd-cluster/s3proxy/internal/caching"
	"github.com/k3s-argocd-cluster/s3proxy/internal/s3"
	"github.com/k3s-argocd-cluster/s3proxy/internal/telemetry"
	logger "github.com/sirupsen/logrus"
)

func handleGetObject(client encryptedClient, key string, bucket string, log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Info("intercepting")
		if req.Header.Get("Range") != "" {
			log.Error("GetObject Range header unsupported")
			http.Error(w, "s3proxy currently does not support Range headers", http.StatusNotImplemented)
			return
		}

		versionID := ""
		if versionIDs, ok := req.URL.Query()["versionId"]; ok && len(versionIDs) > 0 {
			versionID = versionIDs[0]
		}

		service := newObjectService(client)
		result, err := service.get(req.Context(), getObjectInput{
			bucket:               bucket,
			key:                  key,
			versionID:            versionID,
			sseCustomerAlgorithm: req.Header.Get("x-amz-server-side-encryption-customer-algorithm"),
			sseCustomerKey:       req.Header.Get("x-amz-server-side-encryption-customer-key"),
			sseCustomerKeyMD5:    req.Header.Get("x-amz-server-side-encryption-customer-key-MD5"),
		})
		if err != nil {
			writeS3Error(w, err, log)
			return
		}
		defer result.body.Close()

		for key, values := range result.headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		requestID := uuid.New().String()
		select {
		case <-req.Context().Done():
			log.WithField("requestID", requestID).Info("Request was canceled by client")
			return
		default:
			w.WriteHeader(http.StatusOK)
			n, err := io.Copy(w, result.body)
			if err != nil {
				if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
					log.WithField("requestID", requestID).Info("Client closed the connection")
				} else {
					log.WithField("requestID", requestID).WithField("error", err).Error("GetObject sending response")
				}
				return
			}
			telemetry.RecordDownload(n)
		}
	}
}

func handlePutObject(client encryptedClient, tagging bool, key string, bucket string, log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Info("intercepting")

		defer req.Body.Close()

		body, cleanup, payloadSizeFn, mismatchErr, err := preparePutBodyForUpload(req)
		if err != nil {
			log.WithField("error", err).Error("PutObject reading body")
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}
		defer cleanup()

		if mismatchErr != nil {
			marshalled, marshalErr := xml.Marshal(*mismatchErr)
			if marshalErr != nil {
				log.WithField("error", marshalErr).Error("PutObject")
				http.Error(w, fmt.Sprintf("marshalling error: %s", marshalErr.Error()), http.StatusInternalServerError)
				return
			}
			http.Error(w, string(marshalled), http.StatusBadRequest)
			return
		}

		raw := req.Header.Get("x-amz-object-lock-retain-until-date")
		retentionTime, err := parseRetentionTime(raw)
		if err != nil {
			log.WithField("data", raw).WithField("error", err).Error("parsing lock retention time")
			http.Error(w, fmt.Sprintf("parsing x-amz-object-lock-retain-until-date: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		service := newObjectService(client)
		result, err := service.put(req.Context(), putObjectInput{
			bucket:                    bucket,
			key:                       key,
			body:                      body,
			tags:                      req.Header.Get("x-amz-tagging"),
			contentType:               req.Header.Get("Content-Type"),
			metadata:                  getMetadataHeaders(req.Header),
			objectLockLegalHoldStatus: req.Header.Get("x-amz-object-lock-legal-hold"),
			objectLockMode:            req.Header.Get("x-amz-object-lock-mode"),
			objectLockRetainUntilDate: retentionTime,
			sseCustomerAlgorithm:      req.Header.Get("x-amz-server-side-encryption-customer-algorithm"),
			sseCustomerKey:            req.Header.Get("x-amz-server-side-encryption-customer-key"),
			sseCustomerKeyMD5:         req.Header.Get("x-amz-server-side-encryption-customer-key-MD5"),
			tagging:                   tagging,
		})
		if err != nil {
			writeS3Error(w, err, log)
			return
		}

		for key, values := range result.headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		w.WriteHeader(http.StatusOK)
		telemetry.RecordUpload(payloadSizeFn())
	}
}

func preparePutBodyForUpload(req *http.Request) (io.Reader, func(), func() int64, *ContentSHA256MismatchError, error) {
	clientDigest := req.Header.Get("x-amz-content-sha256")
	contentMD5 := req.Header.Get("content-md5")
	needsDigestValidation := clientDigest != "" && clientDigest != "UNSIGNED-PAYLOAD"
	needsMD5Validation := contentMD5 != ""

	if !needsDigestValidation && !needsMD5Validation {
		counter := &countingReader{reader: req.Body}
		return counter, func() {}, counter.BytesRead, nil, nil
	}

	tmpFile, err := os.CreateTemp("", "s3proxy-put-*")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cleanup := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}

	md5Hasher := md5.New() // #nosec G401
	shaHasher := sha256.New()
	multiWriter := io.MultiWriter(tmpFile, md5Hasher, shaHasher)

	bytesCopied, err := io.Copy(multiWriter, req.Body)
	if err != nil {
		cleanup()
		return nil, nil, nil, nil, err
	}

	serverDigest := fmt.Sprintf("%x", shaHasher.Sum(nil))
	if needsDigestValidation && clientDigest != serverDigest {
		cleanup()
		mismatch := NewContentSHA256MismatchError(clientDigest, serverDigest)
		return nil, nil, nil, &mismatch, nil
	}

	if needsMD5Validation {
		if err := validateComputedContentMD5(contentMD5, md5Hasher.Sum(nil)); err != nil {
			cleanup()
			return nil, nil, nil, nil, err
		}
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, nil, nil, nil, err
	}

	return tmpFile, cleanup, func() int64 { return bytesCopied }, nil, nil
}

func validateComputedContentMD5(contentMD5 string, computed []byte) error {
	expected, err := base64.StdEncoding.DecodeString(contentMD5)
	if err != nil {
		return fmt.Errorf("decoding base64: %w", err)
	}
	if len(expected) != md5.Size {
		return fmt.Errorf("content-md5 must be 16 bytes long, got %d bytes", len(expected))
	}
	if !bytes.Equal(expected, computed) {
		return fmt.Errorf("content-md5 mismatch, header is %x, body is %x", expected, computed)
	}
	return nil
}

type countingReader struct {
	reader io.Reader
	n      int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.n += int64(n)
	return n, err
}

func (r *countingReader) BytesRead() int64 {
	return r.n
}

func writeS3Error(w http.ResponseWriter, err error, log *logger.Logger) {
	if errors.Is(err, context.Canceled) {
		log.WithField("error", err).Info("request context canceled while handling s3 operation")
		http.Error(w, "request canceled", http.StatusRequestTimeout)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		log.WithField("error", err).Warn("request deadline exceeded while handling s3 operation")
		http.Error(w, "request timed out", http.StatusGatewayTimeout)
		return
	}

	var httpResponseErr *awshttp.ResponseError
	if errors.As(err, &httpResponseErr) {
		if httpResponseErr.Response != nil {
			for key := range httpResponseErr.Response.Header {
				w.Header().Set(key, httpResponseErr.Response.Header.Get(key))
			}
		}
		statusCode := httpResponseErr.HTTPStatusCode()
		if statusCode < 100 || statusCode > 999 {
			log.WithField("statusCode", statusCode).WithField("error", err).Warn("invalid upstream status code, falling back to 502")
			statusCode = http.StatusBadGateway
		}
		http.Error(w, err.Error(), statusCode)
		return
	}

	log.WithField("error", err).Error("request failed")
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func handleForwards(client *s3.Client, log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		result, err := forward(log, req, client)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		for key := range *result.Header {
			w.Header().Set(key, result.Header.Get(key))
		}

		w.WriteHeader(result.StatusCode)
		if len(*result.Body) == 0 {
			return
		}

		if _, err := w.Write(*result.Body); err != nil {
			log.WithField("error", err).Error("failed to write response")
		}
	}
}

func forward(log *logger.Logger, req *http.Request, client *s3.Client) (caching.CacheElement, error) {
	log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Info("forwarding")

	newReq, err := repackage(req)
	if err != nil {
		log.WithField("error", err).Error("failed to repackage request")
		return caching.CacheElement{}, err
	}

	cfg := client.GetConfig()

	creds, err := cfg.Credentials.Retrieve(req.Context())
	if err != nil {
		log.WithField("error", err).Error("unable to retrieve aws creds")
		return caching.CacheElement{}, err
	}

	signer := v4.NewSigner()
	payloadHash := newReq.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
		newReq.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}

	if err = signer.SignHTTP(req.Context(), creds, newReq, payloadHash, "s3", cfg.Region, time.Now()); err != nil {
		log.WithField("error", err).Error("failed to sign request")
		return caching.CacheElement{}, err
	}

	httpClient := http.DefaultClient
	resp, err := httpClient.Do(newReq)
	if err != nil {
		log.WithField("error", err).Error("do request")
		return caching.CacheElement{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithField("error", err).Error("failed to read response body")
		return caching.CacheElement{}, err
	}

	header := http.Header{}
	for key := range resp.Header {
		header.Add(key, resp.Header.Get(key))
	}

	return caching.CacheElement{
		Header:     &header,
		Body:       &body,
		StatusCode: resp.StatusCode,
	}, nil
}

func handleCreateMultipartUpload(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Debug("intercepting CreateMultipartUpload")
		log.Error("Blocking CreateMultipartUpload request")
		http.Error(w, "s3proxy is configured to block CreateMultipartUpload requests", http.StatusNotImplemented)
	}
}

func handleUploadPart(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Debug("intercepting UploadPart")
		log.Error("Blocking UploadPart request")
		http.Error(w, "s3proxy is configured to block UploadPart requests", http.StatusNotImplemented)
	}
}

func handleCompleteMultipartUpload(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Debug("intercepting CompleteMultipartUpload")
		log.Error("Blocking CompleteMultipartUpload request")
		http.Error(w, "s3proxy is configured to block CompleteMultipartUpload requests", http.StatusNotImplemented)
	}
}

func handleAbortMultipartUpload(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Debug("intercepting AbortMultipartUpload")
		log.Error("Blocking AbortMultipartUpload request")
		http.Error(w, "s3proxy is configured to block AbortMultipartUpload requests", http.StatusNotImplemented)
	}
}
