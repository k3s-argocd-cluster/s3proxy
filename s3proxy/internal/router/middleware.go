package router

import (
	"context"
	"fmt"
	"net/http"

	"github.com/k3s-argocd-cluster/s3proxy/internal/config"
	"github.com/k3s-argocd-cluster/s3proxy/internal/telemetry"
)

type requestStateContextKey struct{}

type middleware func(http.Handler) http.Handler

func (r Router) newMux() http.Handler {
	telemetry.KeepRuntimeMemoryMetric()
	mux := http.NewServeMux()
	mux.Handle("/", r.chain(http.HandlerFunc(r.dispatch),
		r.metricsMiddleware,
		r.recoveryMiddleware,
		r.requestStateMiddleware,
		r.validationMiddleware,
		r.taggingMiddleware,
		r.multipartBlockMiddleware,
		r.invalidateCacheMiddleware,
	))
	return mux
}

func (r Router) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		state := classifyRequest(req)
		capture := newStatusCaptureWriter(w)
		next.ServeHTTP(capture, req)
		telemetry.RecordRequest(req.Method, operationName(state.op), capture.statusCode)
	})
}

func (r Router) chain(base http.Handler, mws ...middleware) http.Handler {
	wrapped := base
	for i := len(mws) - 1; i >= 0; i-- {
		wrapped = mws[i](wrapped)
	}
	return wrapped
}

func (r Router) requestStateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		state := classifyRequest(req)
		next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), requestStateContextKey{}, state)))
	})
}

func requestStateFromContext(ctx context.Context) requestState {
	state, ok := ctx.Value(requestStateContextKey{}).(requestState)
	if !ok {
		return requestState{}
	}
	return state
}

func (r Router) validationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		state := requestStateFromContext(req.Context())
		if state.matchingPath {
			if err := config.ValidateBucketName(state.bucket); err != nil {
				r.log.WithError(err).WithField("bucket", state.bucket).Warn("invalid bucket name")
				http.Error(w, fmt.Sprintf("invalid bucket name: %s", err.Error()), http.StatusBadRequest)
				return
			}
			if err := config.ValidateObjectKey(state.key); err != nil {
				r.log.WithError(err).WithField("key", state.key).Warn("invalid object key")
				http.Error(w, fmt.Sprintf("invalid object key: %s", err.Error()), http.StatusBadRequest)
				return
			}
		}

		if req.Method == http.MethodPut && req.ContentLength > 0 {
			if err := config.ValidateContentLength(req.ContentLength); err != nil {
				r.log.WithError(err).WithField("content_length", req.ContentLength).Warn("invalid content length")
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
				return
			}
		}

		next.ServeHTTP(w, req)
	})
}

func (r Router) taggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !r.tagging && isTaggingAttempt(req) {
			http.Error(w, "object tagging is disabled by configuration", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (r Router) multipartBlockMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch requestStateFromContext(req.Context()).op {
		case opCreateMultipart:
			handleCreateMultipartUpload(r.log).ServeHTTP(w, req)
			return
		case opUploadPart:
			handleUploadPart(r.log).ServeHTTP(w, req)
			return
		case opCompleteMultipart:
			handleCompleteMultipartUpload(r.log).ServeHTTP(w, req)
			return
		case opAbortMultipart:
			handleAbortMultipartUpload(r.log).ServeHTTP(w, req)
			return
		default:
			next.ServeHTTP(w, req)
		}
	})
}

func (r Router) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				r.log.WithField("panic", rec).Error("panic recovered in router")
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, req)
	})
}

type statusCaptureWriter struct {
	http.ResponseWriter
	statusCode int
	wrote      bool
}

func newStatusCaptureWriter(w http.ResponseWriter) *statusCaptureWriter {
	return &statusCaptureWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

func (w *statusCaptureWriter) WriteHeader(statusCode int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (r Router) dispatch(w http.ResponseWriter, req *http.Request) {
	state := requestStateFromContext(req.Context())
	switch state.op {
	case opGetObject:
		handleGetObject(r.crypto, state.key, state.bucket, r.log).ServeHTTP(w, req)
	case opPutObject:
		handlePutObject(r.crypto, r.tagging, state.key, state.bucket, r.log).ServeHTTP(w, req)
	default:
		r.cacheReadMiddleware(handleForwards(r.s3, r.log)).ServeHTTP(w, req)
	}
}
