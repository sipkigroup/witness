#!/bin/sh
# build verifier_swift (Swift + CryptoKit + system ICU; no third-party packages)
cd "$(dirname "$0")" && swiftc -O -swift-version 5 src/*.swift -o aarc
