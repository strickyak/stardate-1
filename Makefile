all: build/stardate

build/stardate: cmd/stardate/main.go server/*.go
	mkdir -p build
	go build -o $@ ./cmd/stardate/

