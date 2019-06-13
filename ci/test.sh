#!/usr/bin/env bash
set -e +o pipefail

# run test / coverage
make
# publish
bash <(curl -s https://codecov.io/bash)