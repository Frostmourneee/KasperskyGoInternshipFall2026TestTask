// Package migrations предоставляет SQL-миграции, встроенные в исполняемый файл.
package migrations

import "embed"

// FS содержит миграции схемы базы данных.
//
//go:embed *.sql
var FS embed.FS
