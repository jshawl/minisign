# Minisign

A ruby implemenation of [Minisign](http://jedisct1.github.io/minisign/).

- [Installation \& Usage](#installation--usage)
  - [Read a public key](#read-a-public-key)
  - [Verify a signature](#verify-a-signature)
  - [Read a private key](#read-a-private-key)
  - [Change the private key's password](#change-the-private-keys-password)
  - [Create a signature](#create-a-signature)
  - [Generate a key pair](#generate-a-key-pair)
- [CLI](#cli)
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
message = File.read("test/example.txt")
signature = Minisign::Signature.new(File.read("test/example.txt.minisig"))
public_key.verify(signature, message)
```

### Read a private key

```rb
password = "password" # optional, if the key is not encrypted
private_key = Minisign::PrivateKey.new(File.read("minisign.key"), password)
```

### Change the private key's password

```rb
password = "new password"
private_key.change_password! password
# or remove the password
private_key.change_password! nil
```

### Create a signature

```rb
file_path = "example.txt"
password = "password"
trusted_comment = "the trusted comment"
untrusted_comment = "the untrusted comment"
signature = private_key.sign(file_path, File.read(file_path), trusted_comment, untrusted_comment)
File.write("#{file_path}.minisig", signature.to_s)
```

### Generate a key pair

```rb
password = "password" # or nil, to generate a private key without encryption
keypair = Minisign::KeyPair.new(password)
keypair.private_key # Minisign::PrivateKey
keypair.public_key # Minisign::PublicKey
```

## CLI

This gem provides an executable `minisign` that implements the CLI
provided by [jedisct1/minisign](https://github.com/jedisct1/minisign).

See command line options [here](https://jedisct1.github.io/minisign/#usage)
or run the executable without any arguments to see usage options.

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
