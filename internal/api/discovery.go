package api

import (
	"context"
	"encoding/json"
	"log"
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
	// Convert the config struct into a valid GetFeatures200JSONResponse struct (since they have the same Features structure)
	// If it errors the recover middleware will throw a 500 error, but this route isn't supposed to error so uhmm it might break some clients (it shouldn't error anyways) :/
	data, err := json.Marshal(s.config)
	if err != nil {
		log.Panicf("couldn't encode config to JSON: %v", err)
	}
	var response GetFeatures200JSONResponse
	if err = json.Unmarshal(data, &response); err != nil {
		log.Panicf("couldn't decode json config into a valid response struct: %v", err)
	}
	return response, nil
}
