build:
	go build -o bin/a.out cmd/exporter/main.go
run: build
	./bin/a.out

include ./cmd/*/sub.mk
ifeq ($(shell test -e cmd/local.mk && echo -n yes),yes)
include local.mk
endif
