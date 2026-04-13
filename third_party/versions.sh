#!/usr/bin/env bash

# Edit this file to pin upstream third-party versions before syncing.

OPENSSL_VERSION=3.6.2
OPENSSL_TAG="openssl-${OPENSSL_VERSION}"
OPENSSL_ARCHIVE_URL="https://github.com/openssl/openssl/archive/refs/tags/${OPENSSL_TAG}.tar.gz"

NGHTTP3_VERSION=1.15.0
NGHTTP3_TAG="v${NGHTTP3_VERSION}"
NGHTTP3_ARCHIVE_URL="https://github.com/ngtcp2/nghttp3/archive/refs/tags/${NGHTTP3_TAG}.tar.gz"

SFPARSE_VERSION=ff7f230e7df2844afef7dc49631cda03a30455f3
SFPARSE_ARCHIVE_URL="https://codeload.github.com/ngtcp2/sfparse/tar.gz/${SFPARSE_VERSION}"
