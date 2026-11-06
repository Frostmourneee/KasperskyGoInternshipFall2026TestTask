package threat_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/threat"
)

type repositoryStub struct {
	calls  int
	method string
	md5    string
	input  threat.Input
	result threat.Threat
	err    error
}

func (r *repositoryStub) Get(_ context.Context, md5 string) (threat.Threat, error) {
	r.calls++
	r.method, r.md5 = "get", md5
	return r.result, r.err
}

func (r *repositoryStub) Create(_ context.Context, md5 string, input threat.Input) (threat.Threat, error) {
	r.calls++
	r.method, r.md5, r.input = "create", md5, input
	return r.result, r.err
}

func (r *repositoryStub) Update(_ context.Context, md5 string, input threat.Input) (threat.Threat, error) {
	r.calls++
	r.method, r.md5, r.input = "update", md5, input
	return r.result, r.err
}

func validInput() threat.Input {
	return threat.Input{Name: "Example threat", ThreatType: "unknown", Severity: "unknown"}
}

func callService(s *threat.Service, method, md5 string, input threat.Input) (threat.Threat, error) {
	switch method {
	case "get":
		return s.Get(context.Background(), md5)
	case "create":
		return s.Create(context.Background(), md5, input)
	default:
		return s.Update(context.Background(), md5, input)
	}
}

func TestServiceNormalizesMD5(t *testing.T) {
	const md5 = "aabbccddeeff00112233445566778899"
	for _, method := range []string{"get", "create", "update"} {
		t.Run(method, func(t *testing.T) {
			want := threat.Threat{MD5: md5, Name: "Stored threat"}
			repo := &repositoryStub{result: want}
			input := validInput()
			got, err := callService(threat.NewService(repo), method, strings.ToUpper(md5), input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if repo.calls != 1 || repo.method != method || repo.md5 != md5 {
				t.Fatalf("unexpected repository call: %+v", repo)
			}
			if method != "get" && !reflect.DeepEqual(repo.input, input) {
				t.Fatalf("input changed: got %+v, want %+v", repo.input, input)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("unexpected result: got %+v, want %+v", got, want)
			}
		})
	}
}

func TestServiceRejectsInvalidMD5(t *testing.T) {
	for _, method := range []string{"get", "create", "update"} {
		t.Run(method, func(t *testing.T) {
			repo := &repositoryStub{}
			_, err := callService(threat.NewService(repo), method, "not-an-md5", validInput())
			if !errors.Is(err, threat.ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
			if repo.calls != 0 {
				t.Fatalf("repository called %d times for invalid MD5", repo.calls)
			}
		})
	}
}

func TestServiceRejectsInvalidInput(t *testing.T) {
	negativeSize := int64(-1)
	cases := []struct {
		name   string
		change func(*threat.Input)
	}{
		{"blank_name", func(input *threat.Input) { input.Name = " \t\n" }},
		{"invalid_threat_type", func(input *threat.Input) { input.ThreatType = "invalid" }},
		{"invalid_severity", func(input *threat.Input) { input.Severity = "critical" }},
		{"negative_file_size", func(input *threat.Input) { input.FileSize = &negativeSize }},
	}
	for _, method := range []string{"create", "update"} {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				repo := &repositoryStub{}
				input := validInput()
				tc.change(&input)
				_, err := callService(threat.NewService(repo), method, "aabbccddeeff00112233445566778899", input)
				if !errors.Is(err, threat.ErrInvalid) {
					t.Fatalf("got %v, want ErrInvalid", err)
				}
				if repo.calls != 0 {
					t.Fatalf("repository called %d times for invalid input", repo.calls)
				}
			})
		}
	}
}

func TestServiceReturnsRepositoryErrors(t *testing.T) {
	cases := []struct {
		method string
		err    error
	}{
		{"get", threat.ErrNotFound},
		{"create", threat.ErrConflict},
		{"update", threat.ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			repo := &repositoryStub{err: tc.err}
			_, err := callService(threat.NewService(repo), tc.method, "aabbccddeeff00112233445566778899", validInput())
			if !errors.Is(err, tc.err) {
				t.Fatalf("got %v, want %v", err, tc.err)
			}
			if repo.calls != 1 {
				t.Fatalf("got %d repository calls, want 1", repo.calls)
			}
		})
	}
}
