package telemetry

import (
	"runtime"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	requestsProcessedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "s3proxy_requests_processed_total",
		Help: "Total number of requests processed by the proxy.",
	}, []string{"method", "operation", "status"})

	uploadFilesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "s3proxy_files_uploaded_total",
		Help: "Total number of objects uploaded via intercepted PutObject.",
	})

	downloadFilesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "s3proxy_files_downloaded_total",
		Help: "Total number of objects downloaded via intercepted GetObject.",
	})

	uploadBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "s3proxy_upload_bytes_total",
		Help: "Total bytes uploaded through intercepted PutObject requests.",
	})

	downloadBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "s3proxy_download_bytes_total",
		Help: "Total bytes downloaded through intercepted GetObject requests.",
	})

	cacheHitsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "s3proxy_cache_hits_total",
		Help: "Total number of cache hits.",
	})

	cacheMissesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "s3proxy_cache_misses_total",
		Help: "Total number of cache misses.",
	})

	cacheStoresTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "s3proxy_cache_stores_total",
		Help: "Total number of responses stored in cache.",
	})

	cacheInvalidationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "s3proxy_cache_invalidations_total",
		Help: "Total number of cache invalidation operations.",
	})

	cacheElementsRemovedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "s3proxy_cache_elements_removed_total",
		Help: "Total number of cache elements removed by invalidations.",
	})

	cacheEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "s3proxy_cache_entries",
		Help: "Current number of entries in cache.",
	})

	cacheBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "s3proxy_cache_bytes",
		Help: "Estimated bytes currently used by cache entries.",
	})

	memoryAllocBytes = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "s3proxy_memory_alloc_bytes",
		Help: "Current memory allocation in bytes (Go runtime Alloc).",
	}, func() float64 {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return float64(ms.Alloc)
	})
)

func RecordRequest(method, operation string, statusCode int) {
	requestsProcessedTotal.WithLabelValues(method, operation, strconv.Itoa(statusCode)).Inc()
}

func RecordUpload(bytes int64) {
	uploadFilesTotal.Inc()
	uploadBytesTotal.Add(float64(bytes))
}

func RecordDownload(bytes int64) {
	downloadFilesTotal.Inc()
	downloadBytesTotal.Add(float64(bytes))
}

func IncCacheHit() {
	cacheHitsTotal.Inc()
}

func IncCacheMiss() {
	cacheMissesTotal.Inc()
}

func IncCacheStore() {
	cacheStoresTotal.Inc()
}

func IncCacheInvalidation() {
	cacheInvalidationsTotal.Inc()
}

func AddCacheElementsRemoved(removed int64) {
	cacheElementsRemovedTotal.Add(float64(removed))
}

func SetCacheStats(entries, bytes int64) {
	cacheEntries.Set(float64(entries))
	cacheBytes.Set(float64(bytes))
}

func KeepRuntimeMemoryMetric() {
	_ = memoryAllocBytes
}
