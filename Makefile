
unittest:
	go vet ./...
	go test -v ./... -coverprofile c.out
	go tool cover -html c.out -o coverage.html

lint:
	@golangci-lint run -v --timeout 600s --build-tags test ./...
