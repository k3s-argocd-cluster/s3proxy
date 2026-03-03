package router

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	awss3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/k3s-argocd-cluster/s3proxy/internal/config"
	logger "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go/modules/minio"
)

type RouterIntegrationSuite struct {
	suite.Suite
	ctx       context.Context
	container *minio.MinioContainer
	admin     *awss3.Client
	router    Router
}

func (s *RouterIntegrationSuite) SetupSuite() {
	s.ctx = context.Background()
	ctr, err := minio.Run(s.ctx, "minio/minio:RELEASE.2024-01-16T16-07-38Z")
	require.NoError(s.T(), err)
	s.container = ctr

	connection, err := ctr.ConnectionString(s.ctx)
	require.NoError(s.T(), err)

	endpoint := "http://" + connection
	require.NoError(s.T(), os.Setenv("S3PROXY_HOST", endpoint))
	require.NoError(s.T(), os.Setenv("S3PROXY_KMS_STATIC_KEY", "integration-test-static-kms-key"))
	require.NoError(s.T(), os.Setenv("AWS_ACCESS_KEY_ID", ctr.Username))
	require.NoError(s.T(), os.Setenv("AWS_SECRET_ACCESS_KEY", ctr.Password))
	require.NoError(s.T(), config.LoadConfig())

	cfg := awsv2.NewConfig()
	cfg.Credentials = credentials.NewStaticCredentialsProvider(ctr.Username, ctr.Password, "")
	cfg.Region = "default"
	cfg.BaseEndpoint = &endpoint
	s.admin = awss3.NewFromConfig(*cfg, func(o *awss3.Options) {
		o.UsePathStyle = true
	})

	s.router, err = New("default", true, "none", logger.New())
	require.NoError(s.T(), err)
}

func (s *RouterIntegrationSuite) TearDownSuite() {
	if s.container != nil {
		require.NoError(s.T(), s.container.Terminate(s.ctx))
	}
}

func (s *RouterIntegrationSuite) SetupTest() {
	s.ensureFixtureObject()
}

func (s *RouterIntegrationSuite) TestServe_RouteMatrix() {
	tests := []struct {
		name           string
		method         string
		path           string
		body           []byte
		headers        map[string]string
		contentLength  int64
		expectStatus   int
		expectContains string
	}{
		{name: "forward root", method: http.MethodGet, path: "/", expectStatus: http.StatusOK},
		{name: "invalid bucket", method: http.MethodGet, path: "/INVALID_BUCKET/key", expectStatus: http.StatusBadRequest},
		{name: "oversized put", method: http.MethodPut, path: "/test/oversized", body: []byte("x"), contentLength: config.MaxObjectSize + 1, expectStatus: http.StatusRequestEntityTooLarge},
		{name: "multipart create blocked", method: http.MethodPost, path: "/test/file?uploads", expectStatus: http.StatusNotImplemented},
		{name: "multipart uploadpart blocked", method: http.MethodPut, path: "/test/file?partNumber=1&uploadId=u1", expectStatus: http.StatusNotImplemented},
		{name: "multipart complete blocked", method: http.MethodPost, path: "/test/file?uploadId=u1", expectStatus: http.StatusNotImplemented},
		{name: "multipart abort blocked", method: http.MethodDelete, path: "/test/file?uploadId=u1", expectStatus: http.StatusNotImplemented},
		{name: "plain get intercept with range", method: http.MethodGet, path: "/test/some-item", headers: map[string]string{"Range": "bytes=0-1"}, expectStatus: http.StatusNotImplemented},
		{name: "unwanted get forwarded", method: http.MethodGet, path: "/test/some-item?tagging", expectStatus: http.StatusOK},
		{name: "plain put intercept digest mismatch", method: http.MethodPut, path: "/test/intercepted-put", body: []byte("payload"), headers: map[string]string{"x-amz-content-sha256": "deadbeef"}, expectStatus: http.StatusBadRequest, expectContains: "XAmzContentSHA256Mismatch"},
		{name: "head object forwarded", method: http.MethodHead, path: "/test/some-item", expectStatus: http.StatusOK},
		{name: "delete object forwarded", method: http.MethodDelete, path: "/test/some-item", expectStatus: http.StatusNoContent},
		{name: "list objects v2 forwarded", method: http.MethodGet, path: "/test?list-type=2", expectStatus: http.StatusOK},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			s.ensureFixtureObject()

			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			if tc.contentLength > 0 {
				req.ContentLength = tc.contentLength
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			s.router.Serve(w, req)

			res := w.Result()
			body := w.Body.String()
			require.Equal(s.T(), tc.expectStatus, res.StatusCode, "response body: %s", body)
			if tc.expectContains != "" {
				require.Contains(s.T(), body, tc.expectContains)
			}
		})
	}
}

func (s *RouterIntegrationSuite) TestServe_AWSClientCommonCalls() {
	tests := []struct {
		name         string
		method       string
		path         string
		headers      map[string]string
		body         []byte
		expectStatus int
	}{
		{name: "GetObject", method: http.MethodGet, path: "/test/some-item", headers: map[string]string{"Range": "bytes=0-1"}, expectStatus: http.StatusNotImplemented},
		{name: "PutObject", method: http.MethodPut, path: "/test/new-item", body: []byte("payload"), headers: map[string]string{"x-amz-content-sha256": "deadbeef"}, expectStatus: http.StatusBadRequest},
		{name: "HeadObject", method: http.MethodHead, path: "/test/some-item", expectStatus: http.StatusOK},
		{name: "DeleteObject", method: http.MethodDelete, path: "/test/some-item", expectStatus: http.StatusNoContent},
		{name: "GetObjectTagging", method: http.MethodGet, path: "/test/some-item?tagging", expectStatus: http.StatusOK},
		{name: "PutObjectTagging", method: http.MethodPut, path: "/test/some-item?tagging", body: []byte("<Tagging></Tagging>"), expectStatus: http.StatusOK},
		{name: "CreateMultipartUpload", method: http.MethodPost, path: "/test/some-item?uploads", expectStatus: http.StatusNotImplemented},
		{name: "UploadPart", method: http.MethodPut, path: "/test/some-item?partNumber=1&uploadId=abc", body: []byte("part"), expectStatus: http.StatusNotImplemented},
		{name: "CompleteMultipartUpload", method: http.MethodPost, path: "/test/some-item?uploadId=abc", expectStatus: http.StatusNotImplemented},
		{name: "AbortMultipartUpload", method: http.MethodDelete, path: "/test/some-item?uploadId=abc", expectStatus: http.StatusNotImplemented},
		{name: "ListObjectsV2", method: http.MethodGet, path: "/test?list-type=2", expectStatus: http.StatusOK},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			s.ensureFixtureObject()

			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			s.router.Serve(w, req)
			require.Equal(s.T(), tc.expectStatus, w.Result().StatusCode, "response body: %s", w.Body.String())
		})
	}
}

func (s *RouterIntegrationSuite) TestServe_NoTaggingRejectsTagging() {
	noTagRouter, err := New("default", false, "none", logger.New())
	require.NoError(s.T(), err)

	tests := []struct {
		name         string
		method       string
		path         string
		headers      map[string]string
		body         []byte
		expectStatus int
	}{
		{
			name:         "put with x-amz-tagging header",
			method:       http.MethodPut,
			path:         "/test/no-tag-header",
			headers:      map[string]string{"x-amz-tagging": "team=dev"},
			body:         []byte("payload"),
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "put object tagging endpoint",
			method:       http.MethodPut,
			path:         "/test/some-item?tagging",
			body:         []byte("<Tagging></Tagging>"),
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		s.Run(tc.name, func() {
			s.ensureFixtureObject()

			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			noTagRouter.Serve(w, req)
			require.Equal(s.T(), tc.expectStatus, w.Result().StatusCode, "response body: %s", w.Body.String())
			require.Contains(s.T(), w.Body.String(), "object tagging is disabled")
		})
	}
}

func (s *RouterIntegrationSuite) TestServe_EncryptionRoundTripAndWrongKeyDecryptionFails() {
	const (
		bucket           = "encryption-test-bucket"
		key              = "encrypted/object.txt"
		staticKeyGood    = "integration-test-static-kms-key"
		staticKeyBad     = "integration-test-static-kms-key-wrong"
		plaintextContent = "secret payload that must not be stored as plaintext"
	)

	_, err := s.admin.CreateBucket(s.ctx, &awss3.CreateBucketInput{Bucket: awsv2.String(bucket)})
	if err != nil {
		var existsErr *awss3types.BucketAlreadyOwnedByYou
		if !errors.As(err, &existsErr) {
			require.NoError(s.T(), err)
		}
	}

	proxySrv := httptest.NewServer(http.HandlerFunc(s.router.Serve))
	defer proxySrv.Close()

	proxyClient := s.newS3ClientForEndpoint(proxySrv.URL)

	_, err = proxyClient.PutObject(s.ctx, &awss3.PutObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
		Body:   bytes.NewReader([]byte(plaintextContent)),
	})
	require.NoError(s.T(), err)

	rawFromBackend, err := s.admin.GetObject(s.ctx, &awss3.GetObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
	})
	require.NoError(s.T(), err)
	defer rawFromBackend.Body.Close()

	rawBytes, err := io.ReadAll(rawFromBackend.Body)
	require.NoError(s.T(), err)
	require.NotEqual(s.T(), []byte(plaintextContent), rawBytes, "backend object must stay encrypted")

	decryptedFromProxy, err := proxyClient.GetObject(s.ctx, &awss3.GetObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
	})
	require.NoError(s.T(), err)
	defer decryptedFromProxy.Body.Close()

	decryptedBytes, err := io.ReadAll(decryptedFromProxy.Body)
	require.NoError(s.T(), err)
	require.Equal(s.T(), []byte(plaintextContent), decryptedBytes)

	require.NoError(s.T(), os.Setenv("S3PROXY_KMS_STATIC_KEY", staticKeyBad))
	require.NoError(s.T(), config.LoadConfig())
	defer func() {
		require.NoError(s.T(), os.Setenv("S3PROXY_KMS_STATIC_KEY", staticKeyGood))
		require.NoError(s.T(), config.LoadConfig())
	}()

	wrongKeyRouter, err := New("default", true, "none", logger.New())
	require.NoError(s.T(), err)
	wrongKeyProxySrv := httptest.NewServer(http.HandlerFunc(wrongKeyRouter.Serve))
	defer wrongKeyProxySrv.Close()

	wrongKeyClient := s.newS3ClientForEndpoint(wrongKeyProxySrv.URL)
	_, err = wrongKeyClient.GetObject(s.ctx, &awss3.GetObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
	})
	require.Error(s.T(), err, "decrypting with a different static key must fail")
}

func (s *RouterIntegrationSuite) newS3ClientForEndpoint(endpoint string) *awss3.Client {
	cfg := awsv2.NewConfig()
	cfg.Credentials = credentials.NewStaticCredentialsProvider(s.container.Username, s.container.Password, "")
	cfg.Region = "default"
	cfg.BaseEndpoint = &endpoint
	return awss3.NewFromConfig(*cfg, func(o *awss3.Options) {
		o.UsePathStyle = true
	})
}

func TestIntegration_RouterSuite(t *testing.T) {
	suite.Run(t, new(RouterIntegrationSuite))
}

func (s *RouterIntegrationSuite) ensureFixtureObject() {
	bucket := "test"
	_, err := s.admin.CreateBucket(s.ctx, &awss3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		var existsErr *awss3types.BucketAlreadyOwnedByYou
		if !errors.As(err, &existsErr) {
			require.NoError(s.T(), err)
		}
	}
	_, err = s.admin.PutObject(s.ctx, &awss3.PutObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String("some-item"),
		Body:   bytes.NewReader([]byte("hello from minio")),
	})
	require.NoError(s.T(), err)
}
