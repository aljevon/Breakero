# Breakero — build automation
#
# Common targets:
#   make build      Build for your current OS/arch into ./breakero
#   make test       Run the test suite
#   make release    Cross-compile Windows/Linux/macOS binaries into ./dist
#   make clean      Remove build artifacts

BINARY      := breakero
PKG         := ./cmd/breakero
VERSION     := 1.0.0
LDFLAGS     := -s -w
BUILDFLAGS  := -trimpath -ldflags "$(LDFLAGS)"
DIST        := dist

.PHONY: all build test vet fmt clean release run

all: build

build:
	go build $(BUILDFLAGS) -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

run: build
	./$(BINARY) -explain

clean:
	rm -rf $(BINARY) $(DIST)

# Cross-compile static, dependency-free binaries for every supported platform.
release: clean
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(BUILDFLAGS) -o $(DIST)/$(BINARY)-windows-amd64.exe $(PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(BUILDFLAGS) -o $(DIST)/$(BINARY)-windows-arm64.exe $(PKG)
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build $(BUILDFLAGS) -o $(DIST)/$(BINARY)-linux-amd64      $(PKG)
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build $(BUILDFLAGS) -o $(DIST)/$(BINARY)-linux-arm64      $(PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build $(BUILDFLAGS) -o $(DIST)/$(BINARY)-darwin-amd64     $(PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build $(BUILDFLAGS) -o $(DIST)/$(BINARY)-darwin-arm64     $(PKG)
	@echo "Built binaries in $(DIST):"
	@ls -lh $(DIST)
