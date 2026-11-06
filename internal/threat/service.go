package threat

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var md5Pattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Service проверяет данные и приводит MD5 к единому регистру перед сохранением.
type Service struct {
	repository Repository
}

// NewService создаёт сервис с переданным хранилищем.
func NewService(repository Repository) *Service {
	return &Service{repository: repository}
}

// Get возвращает угрозу без изменения её данных и временных меток.
func (s *Service) Get(ctx context.Context, md5 string) (Threat, error) {
	md5, err := normalizeMD5(md5)
	if err != nil {
		return Threat{}, err
	}
	return s.repository.Get(ctx, md5)
}

// Create сохраняет новую угрозу; существующий MD5 приводит к ErrConflict.
func (s *Service) Create(ctx context.Context, md5 string, input Input) (Threat, error) {
	md5, err := normalizeMD5(md5)
	if err != nil {
		return Threat{}, err
	}
	if err := validateInput(input); err != nil {
		return Threat{}, err
	}
	return s.repository.Create(ctx, md5, input)
}

// Update полностью заменяет клиентские поля уже существующей угрозы.
func (s *Service) Update(ctx context.Context, md5 string, input Input) (Threat, error) {
	md5, err := normalizeMD5(md5)
	if err != nil {
		return Threat{}, err
	}
	if err := validateInput(input); err != nil {
		return Threat{}, err
	}
	return s.repository.Update(ctx, md5, input)
}

func normalizeMD5(md5 string) (string, error) {
	md5 = strings.ToLower(md5)
	if !md5Pattern.MatchString(md5) {
		return "", fmt.Errorf("%w: MD5 must contain 32 hexadecimal characters", ErrInvalid)
	}
	return md5, nil
}

func validateInput(input Input) error {
	if !utf8.ValidString(input.Name) || strings.ContainsRune(input.Name, '\x00') ||
		utf8.RuneCountInString(input.Name) > 255 || strings.Trim(input.Name, " \t\r\n\f\v") == "" {
		return fmt.Errorf("%w: invalid name", ErrInvalid)
	}
	if !utf8.ValidString(input.Description) || strings.ContainsRune(input.Description, '\x00') ||
		utf8.RuneCountInString(input.Description) > 2000 {
		return fmt.Errorf("%w: invalid description", ErrInvalid)
	}
	switch input.ThreatType {
	case "trojan", "worm", "ransomware", "spyware", "other", "unknown":
	default:
		return fmt.Errorf("%w: invalid threat type", ErrInvalid)
	}
	switch input.Severity {
	case "unknown", "low", "medium", "high":
	default:
		return fmt.Errorf("%w: invalid severity", ErrInvalid)
	}
	if input.FileSize != nil && *input.FileSize < 0 {
		return fmt.Errorf("%w: file size must not be negative", ErrInvalid)
	}
	return nil
}
