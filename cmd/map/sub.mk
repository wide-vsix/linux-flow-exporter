
map-build:
	go build -o bin/map cmd/map/main.go
map-run: map-build
	sudo ./bin/map
