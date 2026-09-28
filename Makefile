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

.PHONY: all build test vet fmt clean release run icons

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

# Regenerate the Windows exe icon and version resource from assets/breakero.ico.
# The generated .syso files are committed, so you only need this after changing
# the icon or version. Requires network access to fetch goversioninfo.
GOVERSIONINFO := go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.7.0
icons:
	$(GOVERSIONINFO) -icon assets/breakero.ico -64      -o cmd/breakero/resource_windows_amd64.syso cmd/breakero/versioninfo.json

# makefat merges the two macOS architectures into one universal Mach-O. It is the
# same tool the Go toolchain uses, run at build time only; nothing is linked into
# the binaries. Pinned for reproducible builds. Requires network access to fetch it.
MAKEFAT := go run github.com/randall77/makefat@v0.0.0-20260406194835-1b91746796b7

# Cross-compile static, dependency-free binaries for every supported platform.
# The macOS file is a universal binary: it runs natively on both Apple Silicon
# (M1/M2/M3) and Intel Macs, so Apple Silicon users never need Rosetta. This keeps
# the release to three files while covering every Mac natively.
release: clean
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(BUILDFLAGS) -o $(DIST)/$(BINARY)-windows-amd64.exe $(PKG)
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build $(BUILDFLAGS) -o $(DIST)/$(BINARY)-linux-amd64      $(PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build $(BUILDFLAGS) -o $(DIST)/_darwin-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build $(BUILDFLAGS) -o $(DIST)/_darwin-arm64 $(PKG)
	$(MAKEFAT) $(DIST)/$(BINARY)-darwin-universal $(DIST)/_darwin-amd64 $(DIST)/_darwin-arm64
	rm -f $(DIST)/_darwin-amd64 $(DIST)/_darwin-arm64
	@echo "Built binaries in $(DIST):"
	@ls -lh $(DIST)
