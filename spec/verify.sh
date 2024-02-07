#!/bin/bash

if [[ "$OSTYPE" == "darwin"* ]]; then
    url="https://github.com/jedisct1/minisign/releases/download/0.11/minisign-0.11-macos.zip"
    curl -sL $url -o test/generated/minisign.zip
    unzip -o test/generated/minisign.zip -d test/generated
else
    url="https://github.com/jedisct1/minisign/releases/download/0.11/minisign-0.11-linux.tar.gz"
    curl -sL $url -o test/generated/minisign.tar.gz
    tar -xvzf test/generated/minisign.tar.gz -C test/generated
    mv test/generated/minisign-linux/x86_64/minisign test/generated/minisign
fi

test/generated/minisign -Vm test/generated/encrypted-key.txt -p test/minisign.pub || exit 1
test/generated/minisign -Vm test/generated/unencrypted-key.txt -p test/unencrypted.pub || exit 1