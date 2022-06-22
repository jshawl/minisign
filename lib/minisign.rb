# frozen_string_literal: true

require 'ed25519'
require 'base64'
require 'openssl'

# `minisign` is a rubygem for verifying {https://jedisct1.github.io/minisign minisign} signatures.
# @author Jesse Shawl
module Minisign
  # Parse a .minisig file's contents
  class Signature
    # @param str [String] The contents of the .minisig file
    # @example
    #   Minisign::Signature.new(File.read('test/example.txt.minisig'))
    def initialize(str)
      @lines = str.split("\n")
    end

    # @return [String] the key id
    # @example
    #   Minisign::Signature.new(File.read('test/example.txt.minisig')).key_id
    #   #=> "E86FECED695E8E0"
    def key_id
      encoded_signature[2..9].bytes.map { |c| c.to_s(16) }.reverse.join.upcase
    end

    # @return [String] the trusted comment
    # @example
    #   Minisign::Signature.new(File.read('test/example.txt.minisig')).trusted_comment
    #   #=> "timestamp:1653934067\tfile:example.txt\thashed"
    def trusted_comment
      @lines[2].split('trusted comment: ')[1]
    end

    def trusted_comment_signature
      Base64.decode64(@lines[3])
    end

    # @return [String] the signature
    def signature
      encoded_signature[10..]
    end

    private

    def encoded_signature
      Base64.decode64(@lines[1])
    end
  end

  # Parse ed25519 verify key from minisign public key
  class PublicKey
    # Parse the ed25519 verify key from the minisign public key
    #
    # @param str [String] The minisign public key
    # @example
    #   Minisign::PublicKey.new('RWTg6JXWzv6GDtDphRQ/x7eg0LaWBcTxPZ7i49xEeiqXVcR+r79OZRWM')
    def initialize(str)
      @public_key = Base64.strict_decode64(str)[10..]
      @verify_key = Ed25519::VerifyKey.new(@public_key)
    end

    def key_id; end

    # Verify a message's signature
    #
    # @param sig [Minisign::Signature]
    # @param message [String] the content that was signed
    # @return [String] the trusted comment
    # @raise Ed25519::VerifyError on invalid signatures
    # @raise RuntimeError on tampered trusted comments
    def verify(sig, message)
      blake = OpenSSL::Digest.new('BLAKE2b512')
      @verify_key.verify(sig.signature, blake.digest(message))
      begin
        @verify_key.verify(sig.trusted_comment_signature, sig.signature + sig.trusted_comment)
      rescue Ed25519::VerifyError
        raise 'Comment signature verification failed'
      end
      "Signature and comment signature verified\nTrusted comment: #{sig.trusted_comment}"
    end
  end
end
