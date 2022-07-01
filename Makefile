build:
	go build -o bin/a.out cmd/exporter/main.go
run: build
	./bin/a.out

include ./cmd/*/sub.mk
