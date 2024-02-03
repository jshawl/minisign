#!/bin/bash

if [[ "$OSTYPE" == "darwin"* ]]; then
    url="https://github.com/jedisct1/minisign/releases/download/0.11/minisign-0.11-macos.zip"
    curl -sL $url -o test/generated/minisign.zip
    unzip -o test/generated/minisign.zip -d test/generated
    test/generated/minisign -Vm test/generated/*.txt -p test/minisign.pub
else
    url="https://github.com/jedisct1/minisign/releases/download/0.11/minisign-0.11-linux.tar.gz"
    curl -sL $url -o test/generated/minisign.tar.gz
    tar -xvzf test/generated/minisign.tar.gz -C test/generated
    test/generated/minisign-linux/x86_64/minisign -Vm test/generated/*.txt -p test/minisign.pub
fi
