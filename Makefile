# Makefile for Pulse proxy

SRC_DIR ?= src

SOURCES = \
	$(SRC_DIR)/app/main.c \
	$(SRC_DIR)/core/pulse.c \
	$(SRC_DIR)/core/socket_io.c \
	$(SRC_DIR)/inbounds/server.c \
	$(SRC_DIR)/manager/config.c \
	$(SRC_DIR)/manager/subscription.c \
	$(SRC_DIR)/outbounds/stream.c \
	$(SRC_DIR)/outbounds/protocol_helpers.c \
	$(SRC_DIR)/outbounds/shadowsocks.c \
	$(SRC_DIR)/outbounds/stubs.c \
	$(SRC_DIR)/outbounds/trojan.c \
	$(SRC_DIR)/outbounds/vmess.c \
	$(SRC_DIR)/outbounds/vless.c \
	$(SRC_DIR)/outbounds/hysteria2.c

OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SOURCES))

ifeq ($(OS),Windows_NT)
SHELL = pwsh
.SHELLFLAGS = -NoProfile -Command

MSYS2_ROOT ?= $(if $(wildcard D:/msys64/mingw64/bin/gcc.exe),D:/msys64,$(if $(wildcard C:/msys64/mingw64/bin/gcc.exe),C:/msys64,D:/msys64))
MINGW_PREFIX ?= $(MSYS2_ROOT)/mingw64
MINGW_BIN ?= $(MINGW_PREFIX)/bin
TOOLCHAIN_NAME := $(notdir $(MINGW_PREFIX))
CC = $(MINGW_BIN)/gcc.exe
PKG_CONFIG = $(MINGW_BIN)/pkg-config.exe
OBJ_DIR ?= obj/$(TOOLCHAIN_NAME)
BIN_DIR ?= bin
EXECUTABLE = $(BIN_DIR)/vless_proxy.exe

ifeq ($(wildcard $(CC)),)
$(error Missing MinGW gcc at $(CC). Set MSYS2_ROOT or CC to a valid toolchain path)
endif
ifeq ($(wildcard $(PKG_CONFIG)),)
$(error Missing pkg-config at $(PKG_CONFIG). Set MSYS2_ROOT or PKG_CONFIG to a valid toolchain path)
endif

DEPS_CFLAGS := $(shell $$env:PATH='$(MINGW_BIN);' + $$env:PATH; & '$(PKG_CONFIG)' --cflags openssl libnghttp3)
DEPS_LIBS := $(shell $$env:PATH='$(MINGW_BIN);' + $$env:PATH; & '$(PKG_CONFIG)' --libs openssl libnghttp3)
RUNTIME_DLLS = \
	$(MINGW_BIN)/libcrypto-3-x64.dll \
	$(MINGW_BIN)/libssl-3-x64.dll \
	$(MINGW_BIN)/libnghttp3-9.dll \
	$(MINGW_BIN)/libgcc_s_seh-1.dll \
	$(MINGW_BIN)/libwinpthread-1.dll \
	$(MINGW_BIN)/libstdc++-6.dll \
	$(MINGW_BIN)/zlib1.dll
CFLAGS = -Wall -Wextra -O2 -I$(SRC_DIR) -I$(SRC_DIR)/core -DNGHTTP3_STATICLIB -DPULSE_HAVE_HYSTERIA2=1 $(DEPS_CFLAGS)
LDFLAGS = -lws2_32 $(DEPS_LIBS)

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) | $(BIN_DIR)
	$$env:PATH='$(MINGW_BIN);' + $$env:PATH; & '$(CC)' $(OBJECTS) -o $@ $(LDFLAGS)
	Copy-Item '$(MINGW_BIN)/libcrypto-3-x64.dll' '$(BIN_DIR)' -Force
	Copy-Item '$(MINGW_BIN)/libssl-3-x64.dll' '$(BIN_DIR)' -Force
	Copy-Item '$(MINGW_BIN)/libnghttp3-9.dll' '$(BIN_DIR)' -Force
	Copy-Item '$(MINGW_BIN)/libgcc_s_seh-1.dll' '$(BIN_DIR)' -Force
	Copy-Item '$(MINGW_BIN)/libwinpthread-1.dll' '$(BIN_DIR)' -Force
	Copy-Item '$(MINGW_BIN)/libstdc++-6.dll' '$(BIN_DIR)' -Force
	Copy-Item '$(MINGW_BIN)/zlib1.dll' '$(BIN_DIR)' -Force

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	New-Item -ItemType Directory -Force (Split-Path '$@') | Out-Null
	$$env:PATH='$(MINGW_BIN);' + $$env:PATH; & '$(CC)' $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	New-Item -ItemType Directory -Force $(OBJ_DIR) | Out-Null

$(BIN_DIR):
	New-Item -ItemType Directory -Force $(BIN_DIR) | Out-Null

clean:
	$$targets = @(); if (Test-Path '$(OBJ_DIR)') { $$targets += '$(OBJ_DIR)' }; if (Test-Path '$(BIN_DIR)') { $$targets += '$(BIN_DIR)' }; if (Test-Path 'obj') { $$legacy = Get-ChildItem 'obj' -Filter '*.o' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName; if ($$legacy) { $$targets += $$legacy } }; if ($$targets.Count -gt 0) { Remove-Item -Recurse -Force $$targets }; $$global:LASTEXITCODE = 0

else
SHELL = /bin/sh

CC ?= gcc
PKG_CONFIG ?= pkg-config
OBJ_DIR ?= obj/linux
BIN_DIR ?= bin/linux
LINUX_PREFIX ?= $(CURDIR)/third_party/prefix/linux
EXECUTABLE = $(BIN_DIR)/vless_proxy
LINUX_PREFIX_PC = $(LINUX_PREFIX)/lib/pkgconfig
PULSE_AUTO_BOOTSTRAP_LINUX ?= 1
LINUX_HAVE_HYSTERIA2 = $(shell [ -f "$(LINUX_PREFIX_PC)/libnghttp3.pc" ] && [ -f "$(LINUX_PREFIX)/include/openssl/quic.h" ] && echo 1 || echo 0)
LINUX_RPATH_FLAG = -Wl,-rpath,'$$ORIGIN/lib'

ifeq ($(LINUX_HAVE_HYSTERIA2),1)
DEPS_CFLAGS = $(shell PKG_CONFIG_PATH="$(LINUX_PREFIX_PC):$(PKG_CONFIG_PATH)" $(PKG_CONFIG) --cflags openssl libnghttp3)
DEPS_LIBS = $(shell PKG_CONFIG_PATH="$(LINUX_PREFIX_PC):$(PKG_CONFIG_PATH)" $(PKG_CONFIG) --libs openssl libnghttp3)
CFLAGS = -Wall -Wextra -O2 -I$(SRC_DIR) -I$(SRC_DIR)/core -DPULSE_HAVE_HYSTERIA2=1 $(DEPS_CFLAGS)
LDFLAGS = -lpthread $(DEPS_LIBS) $(LINUX_RPATH_FLAG)
POST_LINK = mkdir -p $(BIN_DIR)/lib && \
	cp -L $(LINUX_PREFIX)/lib/libcrypto.so* $(BIN_DIR)/lib/ && \
	cp -L $(LINUX_PREFIX)/lib/libssl.so* $(BIN_DIR)/lib/ && \
	cp -L $(LINUX_PREFIX)/lib/libnghttp3.so* $(BIN_DIR)/lib/
else
DEPS_CFLAGS = $(shell $(PKG_CONFIG) --cflags openssl)
DEPS_LIBS = $(shell $(PKG_CONFIG) --libs openssl)
CFLAGS = -Wall -Wextra -O2 -I$(SRC_DIR) -I$(SRC_DIR)/core $(DEPS_CFLAGS)
LDFLAGS = -lpthread $(DEPS_LIBS)
POST_LINK = :
endif

all:
	@if [ "$(PULSE_AUTO_BOOTSTRAP_LINUX)" = "1" ] && { [ ! -f "$(LINUX_PREFIX_PC)/libnghttp3.pc" ] || [ ! -f "$(LINUX_PREFIX)/include/openssl/quic.h" ]; }; then \
		echo "==> Bootstrapping vendored Linux QUIC dependencies for Hysteria2"; \
		bash scripts/build_linux_deps.sh; \
	fi
	@$(MAKE) --no-print-directory PULSE_AUTO_BOOTSTRAP_LINUX=0 build-linux

build-linux: $(EXECUTABLE)

linux-deps:
	bash scripts/build_linux_deps.sh

$(EXECUTABLE): $(OBJECTS) | $(BIN_DIR)
	mkdir -p $(dir $@)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@$(POST_LINK)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

endif

.PHONY: all clean build-linux linux-deps
