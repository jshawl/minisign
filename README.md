# Minisign.rb

A rubygem for verifying [Minisign](http://jedisct1.github.io/minisign/) signatures.

```
irb -Ilib -rminisign
```

```rb
pk = Minisign::PublicKey.new('RWTg6JXWzv6GDtDphRQ/x7eg0LaWBcTxPZ7i49xEeiqXVcR+r79OZRWM')
signature = Minisign::Signature.new(File.read("test/example.txt.minisig"))
message = File.read("test/example.txt")
pk.verify(signature, message)
```
