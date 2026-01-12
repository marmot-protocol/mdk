#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

mkdir -p coverage

echo -e "${CYAN}→${NC} Generating coverage report..."

cargo llvm-cov --all-features --workspace --tests --no-report > /dev/null 2>&1

LCOV_FILE="coverage/lcov.info"
cargo llvm-cov report --lcov --output-path "$LCOV_FILE" > /dev/null 2>&1

if [ ! -f "$LCOV_FILE" ]; then
    echo -e "${RED}✗ Error: Failed to generate coverage report${NC}" >&2
    exit 1
fi

LINES_HIT=$(grep -E "^LH:" "$LCOV_FILE" | awk -F: '{sum+=$2} END {print sum}')
TOTAL_LINES=$(grep -E "^LF:" "$LCOV_FILE" | awk -F: '{sum+=$2} END {print sum}')

if [ -z "$TOTAL_LINES" ] || [ "$TOTAL_LINES" -eq 0 ]; then
    COVERAGE="0.00"
else
    COVERAGE=$(awk "BEGIN {printf \"%.2f\", ($LINES_HIT / $TOTAL_LINES) * 100}")
fi

COVERAGE_INT=$(echo "$COVERAGE" | cut -d. -f1)
if [ "$COVERAGE_INT" -ge 80 ]; then
    COVERAGE_COLOR="${GREEN}"
elif [ "$COVERAGE_INT" -ge 60 ]; then
    COVERAGE_COLOR="${YELLOW}"
else
    COVERAGE_COLOR="${RED}"
fi

cargo llvm-cov report

echo ""
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  Coverage Summary${NC}"
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Lines Covered:${NC}  ${CYAN}${LINES_HIT:-0}${NC} / ${CYAN}${TOTAL_LINES:-0}${NC}"
echo -e "  ${BOLD}Coverage:${NC}      ${COVERAGE_COLOR}${BOLD}${COVERAGE}%${NC}"
echo ""
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"