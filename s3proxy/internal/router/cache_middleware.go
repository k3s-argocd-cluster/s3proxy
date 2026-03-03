package router

import (
	"bytes"
	"net/http"

	"github.com/google/uuid"
	"github.com/k3s-argocd-cluster/s3proxy/internal/caching"
	"github.com/k3s-argocd-cluster/s3proxy/internal/telemetry"
)

func (r Router) invalidateCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodDelete || req.Method == http.MethodPatch || req.Method == http.MethodPost || req.Method == http.MethodPut {
			removed := r.cache.RemoveFromCache(uuid.New().String(), req.URL.Path)
			telemetry.IncCacheInvalidation()
			if removed > 0 {
				telemetry.AddCacheElementsRemoved(removed)
			}
			r.updateCacheStatsMetrics()
		}
		next.ServeHTTP(w, req)
	})
}

func (r Router) cacheReadMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			next.ServeHTTP(w, req)
			return
		}

		requestID := uuid.New().String()
		result, err := r.cache.GetFromCache(requestID, req)
		if err != nil {
			r.log.WithField("error", err).Error("failed to get from cache")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if !result.CachingDesired {
			next.ServeHTTP(w, req)
			return
		}

		if result.ElementFound {
			telemetry.IncCacheHit()
			r.log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Info("from cache")
			for key := range *result.Element.Header {
				w.Header().Set(key, result.Element.Header.Get(key))
			}
			w.WriteHeader(result.Element.StatusCode)
			if len(*result.Element.Body) == 0 {
				return
			}
			if _, err := w.Write(*result.Element.Body); err != nil {
				r.log.WithField("error", err).Error("failed to write cached response")
			}
			return
		}
		telemetry.IncCacheMiss()

		capture := newResponseCapture(w)
		next.ServeHTTP(capture, req)

		if capture.statusCode >= 200 && capture.statusCode < 400 {
			headers := capture.header.Clone()
			body := capture.body.Bytes()
			r.cache.SaveToCache(requestID, caching.Action(req.Method), result.Path, caching.CacheElement{
				Header:     &headers,
				Body:       &body,
				StatusCode: capture.statusCode,
			})
			telemetry.IncCacheStore()
			r.updateCacheStatsMetrics()
		}
	})
}

func (r Router) updateCacheStatsMetrics() {
	stats := r.cache.Stats()
	telemetry.SetCacheStats(stats.Entries, stats.Bytes)
}

type responseCapture struct {
	writer     http.ResponseWriter
	header     http.Header
	body       bytes.Buffer
	statusCode int
	written    bool
}

func newResponseCapture(w http.ResponseWriter) *responseCapture {
	return &responseCapture{
		writer:     w,
		header:     make(http.Header),
		statusCode: http.StatusOK,
	}
}

func (r *responseCapture) Header() http.Header {
	return r.header
}

func (r *responseCapture) Write(b []byte) (int, error) {
	if !r.wroteHeader() {
		r.WriteHeader(http.StatusOK)
	}
	r.body.Write(b)
	return r.writer.Write(b)
}

func (r *responseCapture) WriteHeader(statusCode int) {
	if r.wroteHeader() {
		return
	}
	r.written = true
	r.statusCode = statusCode
	for key, values := range r.header {
		for _, value := range values {
			r.writer.Header().Add(key, value)
		}
	}
	r.writer.WriteHeader(statusCode)
}

func (r *responseCapture) wroteHeader() bool {
	return r.written
}
