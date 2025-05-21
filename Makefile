# Project variables
APP_NAME := oqcd
BUILD_DIR := bin

# Go commands
GO := go
GOFMT := go fmt
GOTEST := go test ./...
GOBUILD := go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/$(APP_NAME)

.PHONY: all build run test fmt clean

all: build

build:
	$(GOBUILD)
	go build -o $(BUILD_DIR)/sendaccountmails ./cmd/sendaccountmails

run: build
	./$(BUILD_DIR)/$(APP_NAME)

test:
	$(GOTEST)

fmt:
	$(GOFMT) ./...

clean:
	rm -rf $(BUILD_DIR)

