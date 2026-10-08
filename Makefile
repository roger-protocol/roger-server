.PHONY: generate build generate-api generate-db

default: build

generate-api:
	go generate ./internal/api

generate-db:
	go generate ./internal/db

generate: generate-api generate-db

build: generate
	go build -o bin/rogerd ./cmd/rogerd

run: generate
	go run ./cmd/rogerd
