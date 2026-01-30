#!/usr/bin/env bash
set -e

echo "Running all regular tests..."
gtimeout 120 cargo test

echo ""
echo "Running slow/ignored tests..."
gtimeout 300 cargo test -- --ignored

echo ""
echo "All tests completed successfully!"
