
BUILD := $(shell git describe --always --dirty)
LDFLAGS=-ldflags "-X github.com/michaelvl/artifact-underwriter/internal/build.Version=$(BUILD)"

.PHONY: build
build:
	go build $(LDFLAGS) -o artifact-underwriter .

.PHONY: lint
lint:
	docker run --rm -v $$(pwd):/app -w /app golangci/golangci-lint:v1.55.2 golangci-lint run -v  --timeout 10m

.PHONY: goimports
goimports:
	goimports -l -w .

.PHONY: pack-policy-bundle
pack-policy-bundle:
	opa build examples/policy -o policybundle.tar.gz
