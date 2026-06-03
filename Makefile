BINARY  = proxy_ob
LDFLAGS = -s -w

TARGETS = \
	dist/$(BINARY)-linux-amd64 \
	dist/$(BINARY)-windows-amd64.exe \
	dist/$(BINARY)-darwin-arm64 \
	dist/$(BINARY)-darwin-amd64

.PHONY: all clean build dist vet

all: dist

vet:
	go vet ./...

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BINARY) .

dist: $(TARGETS)

dist/$(BINARY)-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $@ .

dist/$(BINARY)-windows-amd64.exe:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $@ .

dist/$(BINARY)-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $@ .

dist/$(BINARY)-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $@ .

clean:
	rm -rf dist $(BINARY)
