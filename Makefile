GIT := git -c safe.directory=$(CURDIR)
COUNT := $(shell $(GIT) rev-list --count HEAD)
TAG := $(firstword $(shell $(GIT) tag --points-at HEAD --list "v*"))
BASE_VERSION := $(patsubst v%,%,$(TAG))
VERSION := $(if $(TAG),$(BASE_VERSION)-P$(COUNT),P$(COUNT))
LD_FLAGS := -X Pulse/internal/pulse.AppVersion=$(VERSION) -X Pulse/internal/pulse.BuildNumber=$(COUNT)
WINDOWS_ARTIFACT := Pulse-$(VERSION)-windows-amd64.exe
LINUX_ARTIFACT := Pulse-$(VERSION)-linux-amd64
LINUX_UBUNTU22_ARTIFACT := Pulse-$(VERSION)-linux-ubuntu22-amd64
LINUX_UBUNTU24_ARTIFACT := Pulse-$(VERSION)-linux-ubuntu24-amd64
MACOS_AMD64_ARTIFACT := Pulse-$(VERSION)-darwin-amd64
MACOS_ARM64_ARTIFACT := Pulse-$(VERSION)-darwin-arm64
WINDOWS_ARTIFACT_PATH := build/bin/$(WINDOWS_ARTIFACT)

.PHONY: version print-windows-artifact print-linux-artifact print-linux-ubuntu22-artifact print-linux-ubuntu24-artifact print-macos-amd64-artifact print-macos-arm64-artifact clean clean-windows clean-linux clean-macos clean-pulse compress-windows build build-windows build-linux build-linux-ubuntu22 build-linux-ubuntu24 build-macos build-macos-amd64 build-macos-arm64 test frontend

version:
	@echo Pulse $(VERSION) build $(COUNT)

print-windows-artifact:
	@echo $(WINDOWS_ARTIFACT)

print-linux-artifact:
	@echo $(LINUX_ARTIFACT)

print-linux-ubuntu22-artifact:
	@echo $(LINUX_UBUNTU22_ARTIFACT)

print-linux-ubuntu24-artifact:
	@echo $(LINUX_UBUNTU24_ARTIFACT)

print-macos-amd64-artifact:
	@echo $(MACOS_AMD64_ARTIFACT)

print-macos-arm64-artifact:
	@echo $(MACOS_ARM64_ARTIFACT)

frontend:
	cd frontend && npm run build

test:
	go test ./...

clean: clean-pulse

clean-pulse:
	rm -f build/bin/Pulse-*

clean-windows:
	rm -f build/bin/Pulse-*-windows-amd64.exe

clean-linux:
	rm -f build/bin/Pulse-*-linux-amd64

clean-macos:
	rm -f build/bin/Pulse-*-darwin-amd64 build/bin/Pulse-*-darwin-arm64

compress-windows:
	@if command -v upx >/dev/null 2>&1; then upx --best "$(WINDOWS_ARTIFACT_PATH)"; else echo "upx not found, skip compression"; fi

build: build-windows

build-windows: clean-windows
	wails build -platform windows/amd64 -ldflags "$(LD_FLAGS)" -o $(WINDOWS_ARTIFACT)
	$(MAKE) compress-windows

build-linux: clean-linux
	wails build -platform linux/amd64 -ldflags "$(LD_FLAGS)" -o $(LINUX_ARTIFACT)

build-linux-ubuntu22: clean-linux
	wails build -platform linux/amd64 -ldflags "$(LD_FLAGS)" -o $(LINUX_UBUNTU22_ARTIFACT)

build-linux-ubuntu24: clean-linux
	wails build -platform linux/amd64 -tags webkit2_41 -ldflags "$(LD_FLAGS)" -o $(LINUX_UBUNTU24_ARTIFACT)

build-macos: clean-macos build-macos-amd64 build-macos-arm64

build-macos-amd64:
	wails build -platform darwin/amd64 -ldflags "$(LD_FLAGS)" -o $(MACOS_AMD64_ARTIFACT)

build-macos-arm64:
	wails build -platform darwin/arm64 -ldflags "$(LD_FLAGS)" -o $(MACOS_ARM64_ARTIFACT)
