# Minisign

A rubygem for creating and verifying [Minisign](http://jedisct1.github.io/minisign/) signatures.

- [Installation \& Usage](#installation--usage)
  - [Read a public key](#read-a-public-key)
  - [Verify a signature](#verify-a-signature)
  - [Create a signature](#create-a-signature)
- [Local Development](#local-development)
- [Documentation](#documentation)

## Installation & Usage

```
gem install minisign
```

### Read a public key

```rb
require 'minisign'
public_key = Minisign::PublicKey.new('RWSmKaOrT6m3TGwjwBovgOmlhSbyBUw3hyhnSOYruHXbJa36xHr8rq2M')
# or from a file
public_key = Minisign::PublicKey.new(File.read("test/minisign.pub"))
```

### Verify a signature

```rb
require 'minisign'
public_key = Minisign::PublicKey.new('RWSmKaOrT6m3TGwjwBovgOmlhSbyBUw3hyhnSOYruHXbJa36xHr8rq2M')
message = File.read("test/example.txt")
signature = Minisign::Signature.new(File.read("test/example.txt.minisig"))
public_key.verify(signature, message)
```

The above is equivalent to:

```
minisign -Vm test/example.txt -P RWSmKaOrT6m3TGwjwBovgOmlhSbyBUw3hyhnSOYruHXbJa36xHr8rq2M
```

### Create a signature

```rb
require 'minisign'
file_path = "example.txt"
password = "password"
private_key = Minisign::PrivateKey.new(File.read("minisign.key"), password)
signature = private_key.sign(file_path, File.read(file_path))

File.write("#{file_path}.minisig", signature.to_s)
```

## Local Development

```
irb -Ilib -rminisign
```

## Documentation

The documentation for this gem is published here: 
https://www.rubydoc.info/gems/minisign/

or if working locally:

```
yard server --reload
```
