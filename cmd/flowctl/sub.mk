flowctl-build:
	sudo go build -o bin/flowctl cmd/flowctl/main.go
flowctl-run: flowctl-build
	sudo ./bin/flowctl dump
