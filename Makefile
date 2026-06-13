GIT := git -c safe.directory=$(CURDIR)
COUNT ?= $(shell $(GIT) rev-list --count HEAD)
SERVICE_NUMBER ?= 3
TAG := $(firstword $(shell $(GIT) tag --points-at HEAD --list "v*"))
BASE_VERSION := $(patsubst v%,%,$(TAG))
VERSION ?= $(if $(TAG),$(BASE_VERSION)-P$(COUNT),P$(COUNT))
LD_FLAGS := -X Pulse/internal/pulse.AppVersion=$(VERSION) -X Pulse/internal/pulse.BuildNumber=$(COUNT) -X Pulse/internal/pulse.ServiceBuildNumber=$(SERVICE_NUMBER)
SERVICE_LD_FLAGS := -s -w -H windowsgui
SERVICE_ARTIFACT := internal/pulse/assets/PulseStartupService.exe
ANDROID_VERSION_CODE ?= $(COUNT)
WINDOWS_APP_EMBEDDED_ARTIFACT := Pulse-$(VERSION)-windows-app-embedded-amd64.exe
WINDOWS_SERVICE_EMBEDDED_ARTIFACT := Pulse-$(VERSION)-windows-service-embedded-amd64.exe
ANDROID_ARTIFACT := Pulse-$(VERSION)-android-arm64-v8a.apk
LINUX_ARTIFACT := Pulse-$(VERSION)-linux-amd64
LINUX_UBUNTU22_ARTIFACT := Pulse-$(VERSION)-linux-ubuntu22-amd64
LINUX_UBUNTU24_ARTIFACT := Pulse-$(VERSION)-linux-ubuntu24-amd64
MACOS_AMD64_ARTIFACT := Pulse-$(VERSION)-darwin-amd64
MACOS_ARM64_ARTIFACT := Pulse-$(VERSION)-darwin-arm64
WINDOWS_APP_EMBEDDED_ARTIFACT_PATH := build/bin/$(WINDOWS_APP_EMBEDDED_ARTIFACT)
WINDOWS_SERVICE_EMBEDDED_ARTIFACT_PATH := build/bin/$(WINDOWS_SERVICE_EMBEDDED_ARTIFACT)

.PHONY: version print-windows-app-embedded-artifact print-windows-service-embedded-artifact print-android-artifact print-linux-artifact print-linux-ubuntu22-artifact print-linux-ubuntu24-artifact print-macos-amd64-artifact print-macos-arm64-artifact clean clean-windows clean-windows-app-embedded clean-windows-service-embedded clean-android clean-linux clean-macos clean-pulse compress-windows-app-embedded compress-windows-service-embedded build build-windows-app-mihomo build-windows-service-mihomo build-windows-service-embedded-amd64 build-android build-linux build-linux-ubuntu22 build-linux-ubuntu24 build-macos build-macos-amd64 build-macos-arm64 test frontend

version:
	@echo Pulse $(VERSION) build $(COUNT) service $(SERVICE_NUMBER)

print-windows-app-embedded-artifact:
	@echo $(WINDOWS_APP_EMBEDDED_ARTIFACT)

print-windows-service-embedded-artifact:
	@echo $(WINDOWS_SERVICE_EMBEDDED_ARTIFACT)

print-android-artifact:
	@echo $(ANDROID_ARTIFACT)

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
	rm -f build/bin/Pulse-*-windows-app-embedded-amd64.exe build/bin/Pulse-*-windows-service-embedded-amd64.exe

clean-windows-app-embedded:
	rm -f build/bin/Pulse-*-windows-app-embedded-amd64.exe

clean-windows-service-embedded:
	rm -f build/bin/Pulse-*-windows-service-embedded-amd64.exe

clean-android:
	rm -f build/bin/Pulse-*-android-arm64-v8a.apk

clean-linux:
	rm -f build/bin/Pulse-*-linux-amd64

clean-macos:
	rm -f build/bin/Pulse-*-darwin-amd64 build/bin/Pulse-*-darwin-arm64

compress-windows-app-embedded:
	@if command -v upx >/dev/null 2>&1; then upx --best "$(WINDOWS_APP_EMBEDDED_ARTIFACT_PATH)"; else echo "upx not found, skip compression"; fi

compress-windows-service-embedded:
	@if command -v upx >/dev/null 2>&1; then upx --best "$(WINDOWS_SERVICE_EMBEDDED_ARTIFACT_PATH)"; else echo "upx not found, skip compression"; fi

build: build-windows-app-mihomo

# Generate the Windows service helper with mihomo embedded inside it.
# The asset is gitignored, so the build must produce it on every CI run.
# Output goes to internal/pulse/assets/PulseStartupService.exe where
# //go:embed picks it up.
build-windows-service-embedded-amd64:
	GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -tags pulse_service_embed_mihomo -ldflags "$(SERVICE_LD_FLAGS)" -o $(SERVICE_ARTIFACT) ./cmd/pulse-service

# App-embedded: mihomo runs in the Pulse process, no service helper needed.
build-windows-app-mihomo: clean-windows-app-embedded
	wails build -platform windows/amd64 -tags pulse_embed_mihomo -ldflags "$(LD_FLAGS)" -o $(WINDOWS_APP_EMBEDDED_ARTIFACT)
	$(MAKE) compress-windows-app-embedded

# Service-embedded: mihomo runs inside PulseStartupService.exe; the helper
# is regenerated just before the wails build so the embed inside the
# Go binary always contains the freshly-built one.
build-windows-service-mihomo: clean-windows-service-embedded build-windows-service-embedded-amd64
	wails build -platform windows/amd64 -tags pulse_service_embed_mihomo -ldflags "$(LD_FLAGS)" -o $(WINDOWS_SERVICE_EMBEDDED_ARTIFACT)
	$(MAKE) compress-windows-service-embedded

build-android: clean-android
	@if [ -z "$$ANDROID_HOME" ] && [ -z "$$ANDROID_SDK_ROOT" ]; then echo "ANDROID_HOME or ANDROID_SDK_ROOT is required" >&2; exit 1; fi
	@SDK_DIR="$${ANDROID_HOME:-$${ANDROID_SDK_ROOT}}"; printf 'sdk.dir=%s\n' "$$SDK_DIR" > android/local.properties
	android/native/build-android.sh
	android/native/collect-binaries.sh
	cd android && ./gradlew assembleRelease -PpulseVersionName=$(VERSION) -PpulseVersionCode=$(ANDROID_VERSION_CODE)
	mkdir -p build/bin
	cp android/app/build/outputs/apk/release/app-release.apk build/bin/$(ANDROID_ARTIFACT)

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
