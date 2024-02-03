#!/bin/bash

echo "which curl: $(which curl)"
echo "which unzip: $(which unzip)"
echo "which wget: $(which wget)"
echo "OSTYPE: $OSTYPE"

if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "mac"
else
    echo "linux"
fi