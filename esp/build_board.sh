#!/bin/bash
# build_board.sh — copy board-specific sdkconfig and build
#
# Usage:
#   bash build_board.sh                  # build with default board (elecrow7s3)
#   BOARD=jc3248w535 bash build_board.sh # build for jc3248w535
#   BOARD=jc4880p433 bash build_board.sh # build for jc4880p433
#
# The BOARD variable may also be passed as the first argument:
#   bash build_board.sh jc3248w535

set -e

BOARD=${1:-${BOARD:-elecrow7s3}}

echo "=== Building tiny386 for board: ${BOARD} ==="

if [ ! -f "sdkconfig.${BOARD}" ]; then
    echo "ERROR: sdkconfig.${BOARD} not found"
    exit 1
fi

# Remove any stale sdkconfig so ESP-IDF regenerates it from sdkconfig.${BOARD}
# (used as SDKCONFIG_DEFAULTS in CMakeLists.txt).
rm -f sdkconfig
echo "Removed old sdkconfig; ESP-IDF will regenerate from sdkconfig.${BOARD}"

idf.py -DBOARD="${BOARD}" build
