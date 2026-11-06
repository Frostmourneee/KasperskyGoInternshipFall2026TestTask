package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"

	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/threat"
	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/transport/httpapi/generated"
)

// Options задаёт ограничения HTTP-сервера. Все значения обязательны.
type Options struct {
	APIKey         string
	MaxBodyBytes   int64
	RateLimit      float64
	RateBurst      int
	RequestTimeout time.Duration
}

// New создаёт обработчик API с проверкой запросов и общими ограничениями.
func New(service *threat.Service, opts Options, logger *slog.Logger) (http.Handler, error) {
	if service == nil {
		return nil, errors.New("threat service is required")
	}
	if opts.APIKey == "" || opts.MaxBodyBytes <= 0 || opts.RequestTimeout <= 0 || opts.RateBurst <= 0 || opts.RateLimit <= 0 || math.IsNaN(opts.RateLimit) || math.IsInf(opts.RateLimit, 0) {
		return nil, errors.New("invalid HTTP options")
	}
	if logger == nil {
		logger = slog.Default()
	}
	document, err := generated.GetSwagger()
	if err != nil {
		return nil, fmt.Errorf("load API specification: %w", err)
	}
	// Адрес в документации служит примером и не ограничивает Host запроса.
	document.Servers = nil
	if err := document.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("validate API specification: %w", err)
	}
	router, err := legacy.NewRouter(document)
	if err != nil {
		return nil, fmt.Errorf("create API router: %w", err)
	}
	keyHash := sha256.Sum256([]byte(opts.APIKey))
	authenticate := func(r *http.Request) bool {
		values := r.Header.Values("X-API-Key")
		if len(values) != 1 {
			return false
		}
		providedHash := sha256.Sum256([]byte(values[0]))
		return subtle.ConstantTimeCompare(keyHash[:], providedHash[:]) == 1
	}
	validationOptions := &openapi3filter.Options{
		SkipSettingDefaults: true,
		AuthenticationFunc: func(_ context.Context, input *openapi3filter.AuthenticationInput) error {
			if input.SecuritySchemeName != "ApiKeyAuth" || !authenticate(input.RequestValidationInput.Request) {
				return errors.New("unauthorized")
			}
			return nil
		},
	}
	badRequest := func(w http.ResponseWriter, _ *http.Request, _ error) {
		writeError(w, http.StatusBadRequest, "Invalid request")
	}
	strictHandler := generated.NewStrictHandlerWithOptions(&handler{service: service}, nil, generated.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: badRequest,
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.ErrorContext(r.Context(), "request failed", "method", r.Method, "route", r.Pattern, "error", err)
			writeError(w, http.StatusInternalServerError, "Internal server error")
		},
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "Not found")
	})
	for path, pathItem := range document.Paths.Map() {
		methods := make([]string, 0, len(pathItem.Operations()))
		for method := range pathItem.Operations() {
			methods = append(methods, method)
		}
		slices.Sort(methods)
		allowed := strings.Join(methods, ", ")
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Allow", allowed)
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		})
	}
	apiHandler := generated.HandlerWithOptions(strictHandler, generated.StdHTTPServerOptions{
		BaseRouter:       mux,
		ErrorHandlerFunc: badRequest,
		Middlewares: []generated.MiddlewareFunc{
			validateRequest(router, validationOptions, authenticate, opts.MaxBodyBytes),
		},
	})
	return requestLifecycle(limitRequests(apiHandler, opts.RateLimit, opts.RateBurst), opts.RequestTimeout, logger), nil
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(generated.ErrorResponse{Message: message})
}
