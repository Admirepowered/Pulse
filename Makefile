GIT := git -c safe.directory=$(CURDIR)
COUNT := $(shell $(GIT) rev-list --count HEAD)
TAG := $(firstword $(shell $(GIT) tag --points-at HEAD --list "v*"))
BASE_VERSION := $(patsubst v%,%,$(TAG))
VERSION := $(if $(TAG),$(BASE_VERSION)-P$(COUNT),P$(COUNT))
LD_FLAGS := -X Pulse/internal/pulse.AppVersion=$(VERSION) -X Pulse/internal/pulse.BuildNumber=$(COUNT)
WINDOWS_ARTIFACT := Pulse-$(VERSION)-windows-amd64.exe
LINUX_ARTIFACT := Pulse-$(VERSION)-linux-amd64
MACOS_AMD64_ARTIFACT := Pulse-$(VERSION)-darwin-amd64
MACOS_ARM64_ARTIFACT := Pulse-$(VERSION)-darwin-arm64

.PHONY: version print-windows-artifact print-linux-artifact print-macos-amd64-artifact print-macos-arm64-artifact build build-windows build-linux build-macos build-macos-amd64 build-macos-arm64 test frontend

version:
	@echo Pulse $(VERSION) build $(COUNT)

print-windows-artifact:
	@echo $(WINDOWS_ARTIFACT)

print-linux-artifact:
	@echo $(LINUX_ARTIFACT)

print-macos-amd64-artifact:
	@echo $(MACOS_AMD64_ARTIFACT)

print-macos-arm64-artifact:
	@echo $(MACOS_ARM64_ARTIFACT)

frontend:
	cd frontend && npm run build

test:
	go test ./...

build: build-windows

build-windows:
	wails build -platform windows/amd64 -ldflags "$(LD_FLAGS)" -o $(WINDOWS_ARTIFACT)

build-linux:
	wails build -platform linux/amd64 -ldflags "$(LD_FLAGS)" -o $(LINUX_ARTIFACT)

build-macos: build-macos-amd64 build-macos-arm64

build-macos-amd64:
	wails build -platform darwin/amd64 -ldflags "$(LD_FLAGS)" -o $(MACOS_AMD64_ARTIFACT)

build-macos-arm64:
	wails build -platform darwin/arm64 -ldflags "$(LD_FLAGS)" -o $(MACOS_ARM64_ARTIFACT)
