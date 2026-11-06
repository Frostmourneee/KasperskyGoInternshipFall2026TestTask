// Package threat содержит модель угрозы и правила работы с ней.
package threat

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("threat not found")
	ErrConflict = errors.New("threat already exists")
	ErrInvalid  = errors.New("invalid threat")
)

// Threat представляет сохранённые сведения об угрозе.
type Threat struct {
	MD5         string
	Name        string
	Description string
	ThreatType  string
	Severity    string
	FileSize    *int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Input содержит поля, которыми управляет клиент. nil означает неизвестный размер.
type Input struct {
	Name        string
	Description string
	ThreatType  string
	Severity    string
	FileSize    *int64
}

// Repository задаёт операции хранения без привязки к конкретной базе данных.
type Repository interface {
	Get(context.Context, string) (Threat, error)
	Create(context.Context, string, Input) (Threat, error)
	Update(context.Context, string, Input) (Threat, error)
}
