package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/k3s-argocd-cluster/s3proxy/internal/config"
	logger "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go/modules/minio"
)

type ProxyE2ESuite struct {
	suite.Suite
	ctx         context.Context
	container   *minio.MinioContainer
	backend     *awss3.Client
	dataPort    int
	opsPort     int
	runCancel   context.CancelFunc
	runErr      chan error
	backendHost string
}

func (s *ProxyE2ESuite) SetupSuite() {
	s.ctx = context.Background()

	ctr, err := minio.Run(s.ctx, "minio/minio:RELEASE.2024-01-16T16-07-38Z")
	require.NoError(s.T(), err)
	s.container = ctr

	connection, err := ctr.ConnectionString(s.ctx)
	require.NoError(s.T(), err)

	s.backendHost = "http://" + connection
	require.NoError(s.T(), os.Setenv("S3PROXY_HOST", s.backendHost))
	require.NoError(s.T(), os.Setenv("S3PROXY_KMS_STATIC_KEY", "integration-test-static-kms-key"))
	require.NoError(s.T(), os.Setenv("AWS_ACCESS_KEY_ID", ctr.Username))
	require.NoError(s.T(), os.Setenv("AWS_SECRET_ACCESS_KEY", ctr.Password))
	require.NoError(s.T(), config.LoadConfig())

	s.backend = s.newS3ClientForEndpoint(s.backendHost)

	s.dataPort = reserveTCPPort(s.T())
	s.opsPort = reserveTCPPort(s.T())

	runCtx, cancel := context.WithCancel(context.Background())
	s.runCancel = cancel
	s.runErr = make(chan error, 1)

	go func() {
		s.runErr <- Run(runCtx, Config{
			NoTLS:     true,
			IP:        "127.0.0.1",
			DataPort:  s.dataPort,
			OpsPort:   s.opsPort,
			Region:    "default",
			NoTagging: false,
			CacheType: "memory",
		}, logger.New())
	}()

	require.NoError(s.T(), waitForHealthz(fmt.Sprintf("http://127.0.0.1:%d/healthz", s.opsPort), 10*time.Second))
}

func (s *ProxyE2ESuite) TearDownSuite() {
	if s.runCancel != nil {
		s.runCancel()
	}

	select {
	case err := <-s.runErr:
		require.NoError(s.T(), err)
	case <-time.After(10 * time.Second):
		s.T().Fatal("proxy run did not exit in time")
	}

	if s.container != nil {
		require.NoError(s.T(), s.container.Terminate(s.ctx))
	}
}

func (s *ProxyE2ESuite) TestProxyServiceE2E_PutGetList() {
	proxy := s.newS3ClientForEndpoint(fmt.Sprintf("http://127.0.0.1:%d", s.dataPort))

	bucket := "proxy-e2e-test"
	key := "path/to/object.txt"
	payload := []byte("hello-through-proxy")

	_, err := proxy.CreateBucket(s.ctx, &awss3.CreateBucketInput{Bucket: awsv2.String(bucket)})
	if err != nil {
		if !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") && !strings.Contains(err.Error(), "BucketAlreadyExists") {
			require.NoError(s.T(), err)
		}
	}

	_, err = proxy.PutObject(s.ctx, &awss3.PutObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(s.T(), err)

	gotObj, err := proxy.GetObject(s.ctx, &awss3.GetObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
	})
	require.NoError(s.T(), err)
	defer gotObj.Body.Close()
	gotPayload, err := io.ReadAll(gotObj.Body)
	require.NoError(s.T(), err)
	require.Equal(s.T(), payload, gotPayload)

	listed, err := proxy.ListObjectsV2(s.ctx, &awss3.ListObjectsV2Input{Bucket: awsv2.String(bucket)})
	require.NoError(s.T(), err)
	require.NotEmpty(s.T(), listed.Contents)

	found := false
	for _, obj := range listed.Contents {
		if obj.Key != nil && *obj.Key == key {
			found = true
			break
		}
	}
	require.True(s.T(), found)
}

func (s *ProxyE2ESuite) TestProxyServiceE2E_BackendStoresCiphertext() {
	proxy := s.newS3ClientForEndpoint(fmt.Sprintf("http://127.0.0.1:%d", s.dataPort))

	bucket := "proxy-e2e-encryption"
	key := "enc/file.bin"
	payload := []byte("this payload must not be stored plaintext")

	_, err := proxy.CreateBucket(s.ctx, &awss3.CreateBucketInput{Bucket: awsv2.String(bucket)})
	if err != nil {
		if !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") && !strings.Contains(err.Error(), "BucketAlreadyExists") {
			require.NoError(s.T(), err)
		}
	}

	_, err = proxy.PutObject(s.ctx, &awss3.PutObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(s.T(), err)

	rawObj, err := s.backend.GetObject(s.ctx, &awss3.GetObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
	})
	require.NoError(s.T(), err)
	defer rawObj.Body.Close()
	rawPayload, err := io.ReadAll(rawObj.Body)
	require.NoError(s.T(), err)
	require.NotEqual(s.T(), payload, rawPayload)
}

func (s *ProxyE2ESuite) TestProxyServiceE2E_PutLargeObject120MiB() {
	proxy := s.newS3ClientForEndpoint(fmt.Sprintf("http://127.0.0.1:%d", s.dataPort))

	bucket := "proxy-e2e-large-object"
	key := "large/120mib.bin"

	_, err := proxy.CreateBucket(s.ctx, &awss3.CreateBucketInput{Bucket: awsv2.String(bucket)})
	if err != nil {
		if !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") && !strings.Contains(err.Error(), "BucketAlreadyExists") {
			require.NoError(s.T(), err)
		}
	}

	const size120MiB = 120 * 1024 * 1024
	payload := bytes.Repeat([]byte("0123456789abcdef"), size120MiB/16)
	expectedDigest := sha256.Sum256(payload)

	_, err = proxy.PutObject(s.ctx, &awss3.PutObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(s.T(), err)

	obj, err := proxy.GetObject(s.ctx, &awss3.GetObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
	})
	require.NoError(s.T(), err)
	defer obj.Body.Close()

	h := sha256.New()
	n, err := io.Copy(h, obj.Body)
	require.NoError(s.T(), err)
	require.Equal(s.T(), int64(size120MiB), n)
	require.Equal(s.T(), expectedDigest[:], h.Sum(nil))
}

func (s *ProxyE2ESuite) TestProxyServiceE2E_MetricsAreUpdated() {
	proxy := s.newS3ClientForEndpoint(fmt.Sprintf("http://127.0.0.1:%d", s.dataPort))
	metricsURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", s.opsPort)

	beforeReq := metricSum(s.T(), metricsURL, "s3proxy_requests_processed_total")
	beforeUploads := metricValue(s.T(), metricsURL, "s3proxy_files_uploaded_total")
	beforeDownloads := metricValue(s.T(), metricsURL, "s3proxy_files_downloaded_total")
	beforeUploadBytes := metricValue(s.T(), metricsURL, "s3proxy_upload_bytes_total")
	beforeDownloadBytes := metricValue(s.T(), metricsURL, "s3proxy_download_bytes_total")
	beforeCacheHits := metricValue(s.T(), metricsURL, "s3proxy_cache_hits_total")
	beforeCacheMisses := metricValue(s.T(), metricsURL, "s3proxy_cache_misses_total")
	beforeCacheStores := metricValue(s.T(), metricsURL, "s3proxy_cache_stores_total")
	beforeInvalidations := metricValue(s.T(), metricsURL, "s3proxy_cache_invalidations_total")
	beforeRemoved := metricValue(s.T(), metricsURL, "s3proxy_cache_elements_removed_total")

	bucket := "proxy-e2e-metrics"
	key := "object.txt"
	payload := []byte("metrics-payload")

	_, err := proxy.CreateBucket(s.ctx, &awss3.CreateBucketInput{Bucket: awsv2.String(bucket)})
	if err != nil {
		if !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") && !strings.Contains(err.Error(), "BucketAlreadyExists") {
			require.NoError(s.T(), err)
		}
	}

	_, err = proxy.ListObjectsV2(s.ctx, &awss3.ListObjectsV2Input{Bucket: awsv2.String(bucket)})
	require.NoError(s.T(), err)
	_, err = proxy.ListObjectsV2(s.ctx, &awss3.ListObjectsV2Input{Bucket: awsv2.String(bucket)})
	require.NoError(s.T(), err)

	_, err = proxy.PutObject(s.ctx, &awss3.PutObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(s.T(), err)

	got, err := proxy.GetObject(s.ctx, &awss3.GetObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
	})
	require.NoError(s.T(), err)
	defer got.Body.Close()
	_, err = io.Copy(io.Discard, got.Body)
	require.NoError(s.T(), err)

	afterReq := metricSum(s.T(), metricsURL, "s3proxy_requests_processed_total")
	afterUploads := metricValue(s.T(), metricsURL, "s3proxy_files_uploaded_total")
	afterDownloads := metricValue(s.T(), metricsURL, "s3proxy_files_downloaded_total")
	afterUploadBytes := metricValue(s.T(), metricsURL, "s3proxy_upload_bytes_total")
	afterDownloadBytes := metricValue(s.T(), metricsURL, "s3proxy_download_bytes_total")
	afterCacheHits := metricValue(s.T(), metricsURL, "s3proxy_cache_hits_total")
	afterCacheMisses := metricValue(s.T(), metricsURL, "s3proxy_cache_misses_total")
	afterCacheStores := metricValue(s.T(), metricsURL, "s3proxy_cache_stores_total")
	afterInvalidations := metricValue(s.T(), metricsURL, "s3proxy_cache_invalidations_total")
	afterRemoved := metricValue(s.T(), metricsURL, "s3proxy_cache_elements_removed_total")
	cacheEntries := metricValue(s.T(), metricsURL, "s3proxy_cache_entries")
	cacheBytes := metricValue(s.T(), metricsURL, "s3proxy_cache_bytes")
	memAlloc := metricValue(s.T(), metricsURL, "s3proxy_memory_alloc_bytes")

	require.GreaterOrEqual(s.T(), afterReq-beforeReq, float64(5))
	require.Equal(s.T(), beforeUploads+1, afterUploads)
	require.Equal(s.T(), beforeDownloads+1, afterDownloads)
	require.GreaterOrEqual(s.T(), afterUploadBytes-beforeUploadBytes, float64(len(payload)))
	require.GreaterOrEqual(s.T(), afterDownloadBytes-beforeDownloadBytes, float64(len(payload)))
	require.GreaterOrEqual(s.T(), afterCacheHits-beforeCacheHits, float64(1))
	require.GreaterOrEqual(s.T(), afterCacheMisses-beforeCacheMisses, float64(1))
	require.GreaterOrEqual(s.T(), afterCacheStores-beforeCacheStores, float64(1))
	require.GreaterOrEqual(s.T(), afterInvalidations-beforeInvalidations, float64(1))
	require.GreaterOrEqual(s.T(), afterRemoved-beforeRemoved, float64(1))
	require.GreaterOrEqual(s.T(), cacheEntries, float64(0))
	require.GreaterOrEqual(s.T(), cacheBytes, float64(0))
	require.Greater(s.T(), memAlloc, float64(0))
}

func (s *ProxyE2ESuite) TestProxyServiceE2E_CacheTypeNone() {
	dataPort := reserveTCPPort(s.T())
	opsPort := reserveTCPPort(s.T())
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(runCtx, Config{
			NoTLS:     true,
			IP:        "127.0.0.1",
			DataPort:  dataPort,
			OpsPort:   opsPort,
			Region:    "default",
			NoTagging: false,
			CacheType: "none",
		}, logger.New())
	}()
	require.NoError(s.T(), waitForHealthz(fmt.Sprintf("http://127.0.0.1:%d/healthz", opsPort), 10*time.Second))
	defer func() {
		cancel()
		select {
		case err := <-runErr:
			require.NoError(s.T(), err)
		case <-time.After(10 * time.Second):
			s.T().Fatal("cache=none proxy run did not exit in time")
		}
	}()

	proxy := s.newS3ClientForEndpoint(fmt.Sprintf("http://127.0.0.1:%d", dataPort))
	metricsURL := fmt.Sprintf("http://127.0.0.1:%d/metrics", opsPort)

	beforeHits := metricValue(s.T(), metricsURL, "s3proxy_cache_hits_total")
	beforeMisses := metricValue(s.T(), metricsURL, "s3proxy_cache_misses_total")
	beforeStores := metricValue(s.T(), metricsURL, "s3proxy_cache_stores_total")
	beforeEntries := metricValue(s.T(), metricsURL, "s3proxy_cache_entries")
	beforeBytes := metricValue(s.T(), metricsURL, "s3proxy_cache_bytes")

	bucket := "proxy-e2e-cache-none"
	key := "none-cache-object.txt"
	payload := []byte("cache-none-payload")

	_, err := proxy.CreateBucket(s.ctx, &awss3.CreateBucketInput{Bucket: awsv2.String(bucket)})
	if err != nil {
		if !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") && !strings.Contains(err.Error(), "BucketAlreadyExists") {
			require.NoError(s.T(), err)
		}
	}

	_, err = proxy.ListObjectsV2(s.ctx, &awss3.ListObjectsV2Input{Bucket: awsv2.String(bucket)})
	require.NoError(s.T(), err)
	_, err = proxy.ListObjectsV2(s.ctx, &awss3.ListObjectsV2Input{Bucket: awsv2.String(bucket)})
	require.NoError(s.T(), err)

	_, err = proxy.PutObject(s.ctx, &awss3.PutObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(s.T(), err)

	got, err := proxy.GetObject(s.ctx, &awss3.GetObjectInput{
		Bucket: awsv2.String(bucket),
		Key:    awsv2.String(key),
	})
	require.NoError(s.T(), err)
	defer got.Body.Close()
	body, err := io.ReadAll(got.Body)
	require.NoError(s.T(), err)
	require.Equal(s.T(), payload, body)

	afterHits := metricValue(s.T(), metricsURL, "s3proxy_cache_hits_total")
	afterMisses := metricValue(s.T(), metricsURL, "s3proxy_cache_misses_total")
	afterStores := metricValue(s.T(), metricsURL, "s3proxy_cache_stores_total")
	afterEntries := metricValue(s.T(), metricsURL, "s3proxy_cache_entries")
	afterBytes := metricValue(s.T(), metricsURL, "s3proxy_cache_bytes")

	require.Equal(s.T(), beforeHits, afterHits, "cache hits should not increase with cache=none")
	require.GreaterOrEqual(s.T(), afterMisses-beforeMisses, float64(2))
	require.GreaterOrEqual(s.T(), afterStores-beforeStores, float64(2))
	require.Equal(s.T(), float64(0), afterEntries)
	require.Equal(s.T(), float64(0), afterBytes)
	require.Equal(s.T(), float64(0), beforeEntries)
	require.Equal(s.T(), float64(0), beforeBytes)
}

func (s *ProxyE2ESuite) newS3ClientForEndpoint(endpoint string) *awss3.Client {
	cfg := awsv2.NewConfig()
	cfg.Credentials = credentials.NewStaticCredentialsProvider(s.container.Username, s.container.Password, "")
	cfg.Region = "default"
	cfg.BaseEndpoint = &endpoint
	return awss3.NewFromConfig(*cfg, func(o *awss3.Options) {
		o.UsePathStyle = true
	})
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	require.NoError(t, ln.Close())
	return port
}

func waitForHealthz(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec // test probe to local ephemeral endpoint
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("healthz not ready before timeout")
}

func TestIntegration_ProxyE2ESuite(t *testing.T) {
	suite.Run(t, new(ProxyE2ESuite))
}

func metricValue(t *testing.T, metricsURL string, metricName string) float64 {
	t.Helper()
	body := metricsBody(t, metricsURL)
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, metricName+" ") {
			var name string
			var value float64
			_, err := fmt.Sscanf(line, "%s %f", &name, &value)
			require.NoError(t, err)
			return value
		}
	}
	require.FailNowf(t, "metric not found", "metric %s not found", metricName)
	return 0
}

func metricSum(t *testing.T, metricsURL string, metricName string) float64 {
	t.Helper()
	body := metricsBody(t, metricsURL)
	scanner := bufio.NewScanner(strings.NewReader(body))
	var sum float64
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, metricName+"{") || strings.HasPrefix(line, metricName+" ") {
			var name string
			var value float64
			_, err := fmt.Sscanf(line, "%s %f", &name, &value)
			require.NoError(t, err)
			sum += value
		}
	}
	return sum
}

func metricsBody(t *testing.T, metricsURL string) string {
	t.Helper()
	resp, err := http.Get(metricsURL) //nolint:gosec // local test endpoint
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(raw)
}
