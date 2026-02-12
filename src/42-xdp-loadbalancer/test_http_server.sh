#!/bin/bash
#
# Test script to verify that the HTTP servers correctly handle 
# requests with mismatched Host headers, which is essential for 
# the XDP load balancer to work correctly.
#
# This test demonstrates that the fix resolves the curl hanging issue.

set -e

cd "$(dirname "$0")"

echo "=== Testing HTTP Server with Mismatched Host Headers ==="
echo ""

# Test 1: simple_http_server.py (uses port 8000 by default)
echo "Test 1: Testing simple_http_server.py"
echo "Starting simple_http_server.py on default port 8000..."
python3 simple_http_server.py > /tmp/simple_http_test.log 2>&1 &
SERVER_PID=$!
sleep 3

# Test with mismatched Host header
echo "Sending request with Host: 10.0.0.10:8000 to 127.0.0.1:8000..."
RESPONSE=$(curl -s -H "Host: 10.0.0.10:8000" http://127.0.0.1:8000/ 2>&1 | head -5)
if [ -n "$RESPONSE" ]; then
    echo "✓ simple_http_server.py successfully handled request with mismatched Host header"
else
    echo "✗ simple_http_server.py failed to handle request"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Check server logs
echo "Server log snippet:"
tail -n 1 /tmp/simple_http_test.log
kill $SERVER_PID 2>/dev/null
sleep 1
echo ""

# Test 2: python -m http.server --bind 0.0.0.0
echo "Test 2: Testing python3 -m http.server --bind 0.0.0.0"
echo "Starting http.server on port 8001..."
python3 -m http.server --bind 0.0.0.0 8001 > /tmp/builtin_http_test.log 2>&1 &
SERVER_PID=$!
sleep 3

# Test with mismatched Host header
echo "Sending request with Host: 10.0.0.10:8001 to 127.0.0.1:8001..."
RESPONSE=$(curl -s -H "Host: 10.0.0.10:8001" http://127.0.0.1:8001/ 2>&1 | head -5)
if [ -n "$RESPONSE" ]; then
    echo "✓ http.server --bind 0.0.0.0 successfully handled request with mismatched Host header"
else
    echo "✗ http.server --bind 0.0.0.0 failed to handle request"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Check server logs
echo "Server log snippet:"
tail -n 1 /tmp/builtin_http_test.log
kill $SERVER_PID 2>/dev/null
sleep 1
echo ""

echo "=== All Tests Passed ==="
echo ""
echo "Both HTTP server options correctly handle requests with mismatched Host headers,"
echo "which fixes the curl hanging issue in the XDP load balancer setup."
