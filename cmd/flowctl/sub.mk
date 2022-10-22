flowctl-build:
	CGO_ENABLED=0 go build -o bin/flowctl cmd/flowctl/main.go
