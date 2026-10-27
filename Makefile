VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
MODULE  := github.com/adee42/mcp-server-control
LDFLAGS := -s -w -X $(MODULE)/internal/server.Version=$(VERSION) -X $(MODULE)/internal/mcpserver.Version=$(VERSION)
GO      := CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)"
EXT     := $(if $(filter windows,$(shell go env GOHOSTOS)),.exe,)

.PHONY: all plugin server mcpb release test vet clean

all: plugin server

# sc-mcp for this machine, where the Claude plugin expects it.
plugin:
	$(GO) -o plugin/bin/sc-mcp$(EXT) ./cmd/sc-mcp

server:
	GOOS=linux GOARCH=amd64 $(GO) -o bin/sc-server-linux-amd64 ./cmd/sc-server
	GOOS=linux GOARCH=arm64 $(GO) -o bin/sc-server-linux-arm64 ./cmd/sc-server

# Claude Desktop bundle (needs Node.js for the mcpb packer).
MCPB_TARGETS := windows/amd64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64
mcpb:
	rm -f mcpb/server/sc-mcp-*
	$(foreach t,$(MCPB_TARGETS),GOOS=$(word 1,$(subst /, ,$(t))) GOARCH=$(word 2,$(subst /, ,$(t))) \
		$(GO) -o mcpb/server/sc-mcp-$(subst /,-,$(t))$(if $(findstring windows,$(t)),.exe,) ./cmd/sc-mcp;)
	# The bundle ships binaries, so it has to carry the third-party license notices.
	go run ./tools/thirdparty -o mcpb/THIRD_PARTY_LICENSES.txt
	npx -y @anthropic-ai/mcpb@2.1.2 validate mcpb/manifest.json
	mkdir -p bin
	npx -y @anthropic-ai/mcpb@2.1.2 pack mcpb bin/server-control.mcpb

# GitHub Release assets: needs a clean, tagged checkout.
RELEASE_ASSETS := sc-server-linux-amd64 sc-server-linux-arm64 server-control.mcpb THIRD_PARTY_LICENSES.txt
release:
	@test -z "$$(git status --porcelain)" || { echo "release builds need a clean working tree" >&2; exit 1; }
	$(MAKE) server mcpb
	cp mcpb/THIRD_PARTY_LICENSES.txt bin/
	cd bin && sha256sum $(RELEASE_ASSETS) > SHA256SUMS && cat SHA256SUMS

test:
	go test ./...

vet:
	go vet ./...
	GOOS=linux go vet ./...

clean:
	rm -rf bin plugin/bin mcpb/server/sc-mcp-* mcpb/THIRD_PARTY_LICENSES.txt
