
map-build:
	go build -o bin/map cmd/map/main.go
map-run: map-build
	./bin/map
