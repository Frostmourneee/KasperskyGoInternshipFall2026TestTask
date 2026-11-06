package httpapi_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/threat"
	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/transport/httpapi"
)

func TestRequestLogging(t *testing.T) {
	const key = "private-api-key"
	const name = "PrivateThreatName"
	const query = "private-query-value"
	const databaseError = "private database failure"
	for _, tc := range []struct {
		name, method, path, body, key, route, level string
		status                                      int
		err                                         error
	}{
		{"created", "POST", "/info", `{"md5":"` + testMD5 + `","name":"` + name + `"}`, key, "POST /info", "INFO", 201, nil},
		{"unauthorized", "GET", "/info/" + testMD5, "", "", "GET /info/{md5}", "WARN", 401, nil},
		{"database failure", "GET", "/info/" + testMD5, "", key, "GET /info/{md5}", "ERROR", 500, errors.New(databaseError)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			opts := httpapi.Options{APIKey: key, MaxBodyBytes: 1024, RateLimit: 1000, RateBurst: 100, RequestTimeout: time.Second}
			h, err := httpapi.New(threat.NewService(&stubRepository{err: tc.err}), opts, logger)
			if err != nil {
				t.Fatal(err)
			}
			response := request(h, tc.method, tc.path+"?debug="+query, tc.body, tc.key, "application/json")
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d", response.Code, tc.status)
			}
			for _, secret := range []string{key, name, query, testMD5} {
				if strings.Contains(output.String(), secret) {
					t.Fatalf("log contains request data: %q", secret)
				}
			}
			lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
			wantLines := 1
			if tc.err != nil {
				wantLines = 2
			}
			if len(lines) != wantLines {
				t.Fatalf("log count = %d, want %d: %s", len(lines), wantLines, output.String())
			}
			var completed map[string]any
			if err := json.Unmarshal(lines[len(lines)-1], &completed); err != nil {
				t.Fatal(err)
			}
			if completed["msg"] != "request completed" || completed["method"] != tc.method || completed["route"] != tc.route || completed["status"] != float64(tc.status) || completed["level"] != tc.level {
				t.Fatalf("unexpected completion log: %v", completed)
			}
			if duration, ok := completed["duration_ms"].(float64); !ok || duration < 0 {
				t.Fatalf("invalid duration_ms: %v", completed["duration_ms"])
			}
			if tc.err != nil {
				var failed map[string]any
				if err := json.Unmarshal(lines[0], &failed); err != nil {
					t.Fatal(err)
				}
				errorText, _ := failed["error"].(string)
				if failed["msg"] != "request failed" || failed["level"] != "ERROR" || !strings.Contains(errorText, databaseError) {
					t.Fatalf("unexpected failure log: %v", failed)
				}
				if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), databaseError) {
					t.Fatalf("unsafe error response: %s", response.Body)
				}
			}
		})
	}
}
