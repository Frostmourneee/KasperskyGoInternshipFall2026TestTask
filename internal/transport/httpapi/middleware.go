package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"golang.org/x/time/rate"
)

func validateRequest(router routers.Router, options *openapi3filter.Options, authenticate func(*http.Request) bool, maxBodyBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ServeMux направляет HEAD к GET, но контракт поддерживает только GET.
			if r.Method == http.MethodHead {
				w.Header().Set("Allow", "GET, PUT")
				writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
				return
			}
			if !authenticate(r) {
				writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				if !prepareBody(w, r, maxBodyBytes) {
					return
				}
			}
			route, params, err := router.FindRoute(r)
			if err != nil {
				writeError(w, http.StatusBadRequest, "Invalid request")
				return
			}
			input := &openapi3filter.RequestValidationInput{
				Request:    r,
				PathParams: params,
				Route:      route,
				Options:    options,
			}
			if err := openapi3filter.ValidateRequest(r.Context(), input); err != nil {
				// Ошибки валидатора содержат значения запроса и не передаются клиенту.
				writeError(w, http.StatusBadRequest, "Invalid request")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func prepareBody(w http.ResponseWriter, r *http.Request, maxBodyBytes int64) bool {
	if r.Body == nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return false
	}
	limited := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer limited.Close()
	body, err := io.ReadAll(limited)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "Request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "Invalid request")
		}
		return false
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Unsupported media type")
		return false
	}
	// Проверка всего тела исключает второе JSON-значение и данные после него.
	if !utf8.Valid(body) || !json.Valid(body) {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return true
}

func limitRequests(next http.Handler, requestsPerSecond float64, burst int) http.Handler {
	limiter := rate.NewLimiter(rate.Limit(requestsPerSecond), burst)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		if !limiter.AllowN(now, 1) {
			seconds := math.Ceil((1 - limiter.TokensAt(now)) / requestsPerSecond)
			seconds = math.Max(1, math.Min(seconds, math.MaxInt32))
			w.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
			writeError(w, http.StatusTooManyRequests, "Too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestLifecycle(next http.Handler, timeout time.Duration, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
		response := &responseWriter{ResponseWriter: w}
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Cache-Control", "no-store")
		defer func() {
			if value := recover(); value != nil {
				// Текст паники может содержать секреты, поэтому он не журналируется.
				logger.ErrorContext(ctx, "Request panicked", "method", r.Method, "route", r.Pattern)
				if response.status != 0 {
					panic(http.ErrAbortHandler)
				}
				writeError(response, http.StatusInternalServerError, "Internal server error")
			}
			logger.InfoContext(ctx, "Request completed", "method", r.Method, "route", r.Pattern, "status", response.status, "duration_ms", time.Since(started).Milliseconds())
		}()
		next.ServeHTTP(response, r)
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

// Unwrap сохраняет доступ к возможностям исходного ResponseWriter.
func (w *responseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
