// Package httpapi связывает HTTP-контракт с сервисом угроз.
package httpapi

import (
	"context"
	"errors"

	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/threat"
	"github.com/Frostmourneee/KasperskyGoInternshipFall2026TestTask/internal/transport/httpapi/generated"
)

type handler struct {
	service *threat.Service
}

var _ generated.StrictServerInterface = (*handler)(nil)

func (h *handler) CreateThreat(ctx context.Context, request generated.CreateThreatRequestObject) (generated.CreateThreatResponseObject, error) {
	if request.Body == nil {
		return generated.CreateThreat400JSONResponse{BadRequestJSONResponse: generated.BadRequestJSONResponse{Message: "Invalid request"}}, nil
	}
	input := makeInput(request.Body.Name, request.Body.Description, request.Body.ThreatType, request.Body.Severity, request.Body.FileSize)
	result, err := h.service.Create(ctx, request.Body.Md5, input)
	switch {
	case errors.Is(err, threat.ErrConflict):
		return generated.CreateThreat409JSONResponse{ConflictJSONResponse: generated.ConflictJSONResponse{Message: "Threat already exists"}}, nil
	case errors.Is(err, threat.ErrInvalid):
		return generated.CreateThreat400JSONResponse{BadRequestJSONResponse: generated.BadRequestJSONResponse{Message: "Invalid request"}}, nil
	case err != nil:
		return nil, err
	default:
		return generated.CreateThreat201JSONResponse(makeResponse(result)), nil
	}
}

func (h *handler) GetInfoByMd5(ctx context.Context, request generated.GetInfoByMd5RequestObject) (generated.GetInfoByMd5ResponseObject, error) {
	result, err := h.service.Get(ctx, request.Md5)
	switch {
	case errors.Is(err, threat.ErrNotFound):
		return generated.GetInfoByMd5404JSONResponse{NotFoundJSONResponse: generated.NotFoundJSONResponse{Message: "Threat not found"}}, nil
	case errors.Is(err, threat.ErrInvalid):
		return generated.GetInfoByMd5400JSONResponse{BadRequestJSONResponse: generated.BadRequestJSONResponse{Message: "Invalid request"}}, nil
	case err != nil:
		return nil, err
	default:
		return generated.GetInfoByMd5200JSONResponse(makeResponse(result)), nil
	}
}

func (h *handler) UpdateThreat(ctx context.Context, request generated.UpdateThreatRequestObject) (generated.UpdateThreatResponseObject, error) {
	if request.Body == nil {
		return generated.UpdateThreat400JSONResponse{BadRequestJSONResponse: generated.BadRequestJSONResponse{Message: "Invalid request"}}, nil
	}
	input := makeInput(request.Body.Name, request.Body.Description, request.Body.ThreatType, request.Body.Severity, request.Body.FileSize)
	result, err := h.service.Update(ctx, request.Md5, input)
	switch {
	case errors.Is(err, threat.ErrNotFound):
		return generated.UpdateThreat404JSONResponse{NotFoundJSONResponse: generated.NotFoundJSONResponse{Message: "Threat not found"}}, nil
	case errors.Is(err, threat.ErrInvalid):
		return generated.UpdateThreat400JSONResponse{BadRequestJSONResponse: generated.BadRequestJSONResponse{Message: "Invalid request"}}, nil
	case err != nil:
		return nil, err
	default:
		return generated.UpdateThreat200JSONResponse(makeResponse(result)), nil
	}
}

func makeInput(name string, description *string, threatType *generated.ThreatType, severity *generated.Severity, fileSize *int64) threat.Input {
	input := threat.Input{
		Name:       name,
		ThreatType: "unknown",
		Severity:   "unknown",
		FileSize:   fileSize,
	}
	// Значения по умолчанию применяются после проверки схемы, чтобы не принять null.
	if description != nil {
		input.Description = *description
	}
	if threatType != nil {
		input.ThreatType = string(*threatType)
	}
	if severity != nil {
		input.Severity = string(*severity)
	}
	return input
}

func makeResponse(value threat.Threat) generated.ThreatResponse {
	return generated.ThreatResponse{
		Md5:         value.MD5,
		Name:        value.Name,
		Description: value.Description,
		ThreatType:  generated.ThreatType(value.ThreatType),
		Severity:    generated.Severity(value.Severity),
		FileSize:    value.FileSize,
		CreatedAt:   value.CreatedAt.UTC(),
		UpdatedAt:   value.UpdatedAt.UTC(),
	}
}
