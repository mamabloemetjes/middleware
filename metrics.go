package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	HttpDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "api",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request latency",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "path", "status"},
	)

	HttpRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "api",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total HTTP requests",
		},
		[]string{"method", "path", "status"},
	)
)

// PrometheusMetrics implements MetricsCollector using prometheus.
type PrometheusMetrics struct{}

func (p *PrometheusMetrics) RecordRequest(method, path, status string, duration time.Duration) {
	labels := prometheus.Labels{
		"method": method,
		"path":   path,
		"status": status,
	}
	HttpRequests.With(labels).Inc()
	HttpDuration.With(labels).Observe(duration.Seconds())
}

func (mw *Middleware) MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		status := strconv.Itoa(ww.Status())
		mw.metricsCollector.RecordRequest(r.Method, r.URL.Path, status, time.Since(start))
	})
}
