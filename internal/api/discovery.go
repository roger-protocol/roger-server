package api

import (
	"context"
)

func (s *Server) GetVersion(ctx context.Context, request GetVersionRequestObject) (GetVersionResponseObject, error) {
	return GetVersion200JSONResponse{
		Name:              "test",
		NodeVersion:       "v0.2.1",
		SupportedVersions: []string{"v1", "v2", "v3"},
	}, nil
}

func (s *Server) GetFeatures(ctx context.Context, request GetFeaturesRequestObject) (GetFeaturesResponseObject, error) {
	panic("unimplemented")
}
