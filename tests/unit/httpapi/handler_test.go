package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/threat"
	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/transport/httpapi"
)

const testMD5 = "abcdef0123456789abcdef0123456789"

type stubRepository struct {
	value threat.Threat
	err   error
	input threat.Input
	md5   string
}

func (s *stubRepository) Get(_ context.Context, md5 string) (threat.Threat, error) {
	s.md5 = md5
	return s.value, s.err
}
func (s *stubRepository) Create(_ context.Context, md5 string, input threat.Input) (threat.Threat, error) {
	s.md5, s.input = md5, input
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.value = threat.Threat{MD5: md5, Name: input.Name, Description: input.Description, ThreatType: input.ThreatType, Severity: input.Severity, FileSize: input.FileSize, CreatedAt: now, UpdatedAt: now}
	return s.value, s.err
}
func (s *stubRepository) Update(ctx context.Context, md5 string, input threat.Input) (threat.Threat, error) {
	return s.Create(ctx, md5, input)
}

func testHandler(t *testing.T, repo *stubRepository, options ...httpapi.Options) http.Handler {
	t.Helper()
	opts := httpapi.Options{APIKey: "test-key", MaxBodyBytes: 1024, RateLimit: 1000, RateBurst: 100, RequestTimeout: time.Second}
	if len(options) > 0 {
		opts = options[0]
	}
	h, err := httpapi.New(threat.NewService(repo), opts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func request(h http.Handler, method, path, body, key, contentType string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if key != "" {
		r.Header.Set("X-API-Key", key)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestCreateThreat(t *testing.T) {
	repo := &stubRepository{}
	w := request(testHandler(t, repo), "POST", "/info", `{"md5":"ABCDEF0123456789ABCDEF0123456789","name":"Example"}`, "test-key", "application/json")
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body = %s", w.Code, w.Body)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("response must be JSON")
	}
	if repo.md5 != testMD5 || repo.input.Description != "" || repo.input.ThreatType != "unknown" || repo.input.Severity != "unknown" || repo.input.FileSize != nil {
		t.Fatalf("unexpected input: md5=%s input=%+v", repo.md5, repo.input)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 8 || body["md5"] != testMD5 || body["file_size"] != nil || body["name"] != "Example" {
		t.Fatalf("unexpected response: %v", body)
	}
	if body["created_at"] != "2026-01-01T00:00:00Z" || body["updated_at"] != body["created_at"] {
		t.Fatalf("unexpected timestamps: %v", body)
	}
}

func TestGetAndUpdateThreat(t *testing.T) {
	repo := &stubRepository{value: threat.Threat{MD5: testMD5, Name: "Example", ThreatType: "unknown", Severity: "unknown"}}
	h := testHandler(t, repo)
	w := request(h, "GET", "/info/"+strings.ToUpper(testMD5), "", "test-key", "")
	if w.Code != 200 || repo.md5 != testMD5 {
		t.Fatalf("GET status = %d, md5 = %s", w.Code, repo.md5)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["md5"] != testMD5 || body["name"] != "Example" {
		t.Fatalf("unexpected GET response: %v", body)
	}
	w = request(h, "PUT", "/info/"+testMD5, `{"name":"Updated","description":"Details","threat_type":"trojan","severity":"high","file_size":0}`, "test-key", "application/json")
	if w.Code != 200 || repo.input.Name != "Updated" || repo.input.Description != "Details" || repo.input.ThreatType != "trojan" || repo.input.Severity != "high" || repo.input.FileSize == nil || *repo.input.FileSize != 0 {
		t.Fatalf("PUT status = %d, input = %+v", w.Code, repo.input)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["name"] != "Updated" || body["file_size"] != float64(0) {
		t.Fatalf("unexpected PUT response: %v", body)
	}
}

func TestInvalidRequests(t *testing.T) {
	cases := []struct {
		name, method, path, body, key, contentType string
		status                                     int
	}{
		{"missing key", "GET", "/info/" + testMD5, "", "", "", 401},
		{"wrong key", "GET", "/info/" + testMD5, "", "wrong", "", 401},
		{"invalid md5", "GET", "/info/invalid", "", "test-key", "", 400},
		{"blank name", "PUT", "/info/" + testMD5, `{"name":"  "}`, "test-key", "application/json", 400},
		{"null description", "PUT", "/info/" + testMD5, `{"name":"Example","description":null}`, "test-key", "application/json", 400},
		{"unknown field", "PUT", "/info/" + testMD5, `{"name":"Example","extra":true}`, "test-key", "application/json", 400},
		{"malformed json", "POST", "/info", `{`, "test-key", "application/json", 400},
		{"large body", "POST", "/info", strings.Repeat("x", 1025), "test-key", "application/json", 413},
		{"wrong content type", "POST", "/info", `{}`, "test-key", "text/plain", 415},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &stubRepository{}
			w := request(testHandler(t, repo), tc.method, tc.path, tc.body, tc.key, tc.contentType)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d; body = %s", w.Code, tc.status, w.Body)
			}
			if repo.md5 != "" {
				t.Fatal("invalid request reached repository")
			}
		})
	}
}

func TestRepositoryErrors(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		err                      error
		status                   int
	}{
		{"get missing", "GET", "/info/" + testMD5, "", threat.ErrNotFound, 404},
		{"update missing", "PUT", "/info/" + testMD5, `{"name":"Example"}`, threat.ErrNotFound, 404},
		{"duplicate", "POST", "/info", `{"md5":"` + testMD5 + `","name":"Example"}`, threat.ErrConflict, 409},
		{"database failure", "GET", "/info/" + testMD5, "", errors.New("private database details"), 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(testHandler(t, &stubRepository{err: tc.err}), tc.method, tc.path, tc.body, "test-key", "application/json")
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d; body = %s", w.Code, tc.status, w.Body)
			}
			var body struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Message == "" || strings.Contains(w.Body.String(), "private database details") {
				t.Fatalf("unsafe error response: %s", w.Body)
			}
		})
	}
}

func TestRateLimit(t *testing.T) {
	h := testHandler(t, &stubRepository{}, httpapi.Options{APIKey: "test-key", MaxBodyBytes: 1024, RateLimit: 0.000001, RateBurst: 1, RequestTimeout: time.Second})
	first := request(h, "GET", "/info/"+testMD5, "", "test-key", "")
	if first.Code != 200 {
		t.Fatalf("first status = %d", first.Code)
	}
	w := request(h, "GET", "/info/"+testMD5, "", "test-key", "")
	retry, err := strconv.Atoi(w.Header().Get("Retry-After"))
	if w.Code != 429 || err != nil || retry < 1 {
		t.Fatalf("status = %d, Retry-After = %q", w.Code, w.Header().Get("Retry-After"))
	}
}
