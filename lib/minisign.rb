# frozen_string_literal: true

require 'ed25519'
require 'base64'
require 'openssl'

# `minisign` is a rubygem for verifying {https://jedisct1.github.io/minisign minisign} signatures.
# @author Jesse Shawl
module Minisign
  # Parse a .minisig file's contents
  class Signature
    attr_reader :signature, :comment, :comment_signature, :key_id

    # @!attribute [r] signature
    #   @return [String] the ed25519 verify key
    # @!attribute [r] comment_signature
    #   @return [String] the signature for the trusted comment
    # @!attribute [r] comment
    #   @return [String] the trusted comment

    # @param str [String] The contents of the .minisig file
    # @example
    #   Minisign::Signature.new(File.read('test/example.txt.minisig'))
    def initialize(str)
      lines = str.split("\n")
      sig = Base64.decode64(lines[1])
      @key_id = sig[2..9].bytes.map{|c| c.to_s(16)}.reverse.join('').upcase
      @signature = sig[10..]
      @comment = lines[2].split('trusted comment: ')[1]
      @comment_signature = Base64.decode64(lines[3])
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
        @verify_key.verify(sig.comment_signature, sig.signature + sig.comment)
      rescue Ed25519::VerifyError
        raise 'Comment signature verification failed'
      end
      "Signature and comment signature verified\nTrusted comment: #{sig.comment}"
    end
  end
end
