#!/usr/bin/env bash
set -e +o pipefail

ls

make
mv coverage.txt ${GITHUB_WORKSPACE}/coverage.txt