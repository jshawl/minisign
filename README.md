# Minisign

A rubygem for creating and verifying [Minisign](http://jedisct1.github.io/minisign/) signatures.

## Installation & Usage

```
gem install minisign
```

### Verify a signature

```rb
require 'minisign'
public_key = Minisign::PublicKey.new('RWTg6JXWzv6GDtDphRQ/x7eg0LaWBcTxPZ7i49xEeiqXVcR+r79OZRWM')
message = File.read("test/example.txt")
signature = Minisign::Signature.new(File.read("test/example.txt.minisig"))
public_key.verify(signature, message)
```

The above is equivalent to:

```
minisign -Vm test/example.txt -P RWTg6JXWzv6GDtDphRQ/x7eg0LaWBcTxPZ7i49xEeiqXVcR+r79OZRWM
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

## Local Documentation

```
yard server --reload
```
