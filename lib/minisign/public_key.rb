# frozen_string_literal: true

module Minisign
  # Parse ed25519 verify key from minisign public key
  class PublicKey
    include Utils
    # Parse the ed25519 verify key from the minisign public key
    #
    # @param str [String] The minisign public key
    # @example
    #   Minisign::PublicKey.new('RWTg6JXWzv6GDtDphRQ/x7eg0LaWBcTxPZ7i49xEeiqXVcR+r79OZRWM')
    def initialize(str)
      parts = str.split("\n")
      @decoded = Base64.strict_decode64(parts.last)
      @public_key = @decoded[10..]
      @verify_key = Ed25519::VerifyKey.new(@public_key)
    end

    # @return [String] the key id
    # @example
    #   Minisign::PublicKey.new('RWTg6JXWzv6GDtDphRQ/x7eg0LaWBcTxPZ7i49xEeiqXVcR+r79OZRWM').key_id
    #   #=> "E86FECED695E8E0"
    def key_id
      @decoded[2..9].bytes.map { |c| c.to_s(16) }.reverse.join.upcase
    end

    # Verify a message's signature
    #
    # @param sig [Minisign::Signature]
    # @param message [String] the content that was signed
    # @return [String] the trusted comment
    # @raise Ed25519::VerifyError on invalid signatures
    # @raise RuntimeError on tampered trusted comments
    def verify(sig, message)
      ensure_matching_key_ids(sig.key_id, key_id)
      @verify_key.verify(sig.signature, blake2b512(message))
      begin
        @verify_key.verify(sig.trusted_comment_signature, sig.signature + sig.trusted_comment)
      rescue Ed25519::VerifyError
        raise 'Comment signature verification failed'
      end
      "Signature and comment signature verified\nTrusted comment: #{sig.trusted_comment}"
    end

    def to_s
      data = Base64.strict_encode64("Ed#{@decoded[2..9]}#{@public_key}")
      "untrusted comment: minisign public key #{key_id}\n#{data}\n"
    end

    private

    def ensure_matching_key_ids(key_id1, key_id2)
      raise "Signature key id is #{key_id1}\nbut the key id in the public key is #{key_id2}" unless key_id1 == key_id2
    end
  end
end
