# frozen_string_literal: true

require 'ed25519'
require 'base64'
require 'openssl'

module Minisign
  # Parse a .minisig file's contents
  class Signature
    attr_reader :signature, :comment, :comment_signature

    def initialize(str)
      lines = str.split("\n")
      @signature = Base64.decode64(lines[1])[10..]
      @comment = lines[2].split('trusted comment: ')[1]
      @comment_signature = Base64.decode64(lines[3])
    end
  end

  # Parse ed25519 verify key from minisign public key
  class PublicKey
    def initialize(str)
      @public_key = Base64.strict_decode64(str)[10..]
      @verify_key = Ed25519::VerifyKey.new(@public_key)
    end

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
