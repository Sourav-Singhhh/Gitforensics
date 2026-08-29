.PHONY: all build test vet reproducible-build clean

BINARY_NAME=gitforensics
BIN_DIR=bin

all: build

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/gitforensics

test:
	go test -count=1 -v ./...

vet:
	go vet ./...

reproducible-build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOFLAGS=-trimpath go build -o $(BIN_DIR)/$(BINARY_NAME)_1 ./cmd/gitforensics
	CGO_ENABLED=0 GOFLAGS=-trimpath go build -o $(BIN_DIR)/$(BINARY_NAME)_2 ./cmd/gitforensics
	@HASH1=$$(sha256sum $(BIN_DIR)/$(BINARY_NAME)_1 | awk '{print $$1}'); \
	HASH2=$$(sha256sum $(BIN_DIR)/$(BINARY_NAME)_2 | awk '{print $$1}'); \
	echo "Build 1 SHA-256: $$HASH1"; \
	echo "Build 2 SHA-256: $$HASH2"; \
	if [ "$$HASH1" = "$$HASH2" ]; then \
		echo "Reproducible build verification: SUCCESS (Bit-for-bit identical)"; \
		cp $(BIN_DIR)/$(BINARY_NAME)_1 $(BIN_DIR)/$(BINARY_NAME); \
		rm -f $(BIN_DIR)/$(BINARY_NAME)_1 $(BIN_DIR)/$(BINARY_NAME)_2; \
	else \
		echo "Reproducible build verification: FAILED (Hashes differ)"; \
		exit 1; \
	fi

clean:
	rm -rf $(BIN_DIR)
