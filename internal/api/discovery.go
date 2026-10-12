package api

import (
	"context"
	"encoding/json"
)

func (s *Server) GetVersion(ctx context.Context, request GetVersionRequestObject) (GetVersionResponseObject, error) {
	return GetVersion200JSONResponse{
		Name:              s.config.Server.Name,
		NodeDescription:   s.config.Server.Description,
		NodeVersion:       s.config.Server.Version,
		SupportedVersions: []string{"v1"},
	}, nil
}

func (s *Server) GetFeatures(ctx context.Context, request GetFeaturesRequestObject) (GetFeaturesResponseObject, error) {
	data, _ := json.Marshal(s.config)
	var response GetFeatures200JSONResponse
	json.Unmarshal(data, &response)
	return response, nil
}
