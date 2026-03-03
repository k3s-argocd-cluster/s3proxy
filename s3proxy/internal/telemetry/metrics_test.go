package telemetry

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestRequestMetricIncrements(t *testing.T) {
	before := testutil.ToFloat64(requestsProcessedTotal.WithLabelValues("GET", "forward", "200"))
	RecordRequest("GET", "forward", 200)
	after := testutil.ToFloat64(requestsProcessedTotal.WithLabelValues("GET", "forward", "200"))
	require.Equal(t, before+1, after)
}

func TestTransferMetricsIncrement(t *testing.T) {
	uploadFilesBefore := testutil.ToFloat64(uploadFilesTotal)
	uploadBytesBefore := testutil.ToFloat64(uploadBytesTotal)
	downloadFilesBefore := testutil.ToFloat64(downloadFilesTotal)
	downloadBytesBefore := testutil.ToFloat64(downloadBytesTotal)

	RecordUpload(123)
	RecordDownload(456)

	require.Equal(t, uploadFilesBefore+1, testutil.ToFloat64(uploadFilesTotal))
	require.Equal(t, uploadBytesBefore+123, testutil.ToFloat64(uploadBytesTotal))
	require.Equal(t, downloadFilesBefore+1, testutil.ToFloat64(downloadFilesTotal))
	require.Equal(t, downloadBytesBefore+456, testutil.ToFloat64(downloadBytesTotal))
}

func TestCacheMetricsIncrement(t *testing.T) {
	hitBefore := testutil.ToFloat64(cacheHitsTotal)
	missBefore := testutil.ToFloat64(cacheMissesTotal)
	storeBefore := testutil.ToFloat64(cacheStoresTotal)
	invalidationBefore := testutil.ToFloat64(cacheInvalidationsTotal)
	removedBefore := testutil.ToFloat64(cacheElementsRemovedTotal)

	IncCacheHit()
	IncCacheMiss()
	IncCacheStore()
	IncCacheInvalidation()
	AddCacheElementsRemoved(3)

	require.Equal(t, hitBefore+1, testutil.ToFloat64(cacheHitsTotal))
	require.Equal(t, missBefore+1, testutil.ToFloat64(cacheMissesTotal))
	require.Equal(t, storeBefore+1, testutil.ToFloat64(cacheStoresTotal))
	require.Equal(t, invalidationBefore+1, testutil.ToFloat64(cacheInvalidationsTotal))
	require.Equal(t, removedBefore+3, testutil.ToFloat64(cacheElementsRemovedTotal))
}

func TestGaugeMetricsSet(t *testing.T) {
	SetCacheStats(7, 1024)
	require.Equal(t, float64(7), testutil.ToFloat64(cacheEntries))
	require.Equal(t, float64(1024), testutil.ToFloat64(cacheBytes))
}
