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
      @lines = str.split("\n")
      @decoded = Base64.strict_decode64(@lines.last)
    end

    # @return [String] the key id
    # @example
    #   Minisign::PublicKey.new('RWTg6JXWzv6GDtDphRQ/x7eg0LaWBcTxPZ7i49xEeiqXVcR+r79OZRWM').key_id
    #   #=> "E86FECED695E8E0"
    def key_id
      key_id_binary_string.bytes.map { |c| c.to_s(16) }.reverse.join.upcase
    end

    def untrusted_comment
      if @lines.length == 1
        "minisign public key #{key_id}"
      else
        @lines.first.split('untrusted comment: ').last
      end
    end

    # Verify a message's signature
    #
    # @param sig [Minisign::Signature]
    # @param message [String] the content that was signed
    # @return [String] the trusted comment
    # @raise Ed25519::VerifyError on invalid signatures
    # @raise RuntimeError on tampered trusted comments
    def verify(sig, message)
      assert_matching_key_ids!(sig.key_id, key_id)
      ed25519_verify_key.verify(sig.signature, blake2b512(message))
      begin
        ed25519_verify_key.verify(sig.trusted_comment_signature, sig.signature + sig.trusted_comment)
      rescue Ed25519::VerifyError
        raise 'Comment signature verification failed'
      end
      "Signature and comment signature verified\nTrusted comment: #{sig.trusted_comment}"
    end

    def to_s
      "untrusted comment: #{untrusted_comment}\n#{key_data}\n"
    end

    private

    def key_id_binary_string
      @decoded[2..9]
    end

    def ed25519_public_key_binary_string
      @decoded[10..]
    end

    def ed25519_verify_key
      Ed25519::VerifyKey.new(ed25519_public_key_binary_string)
    end

    def key_data
      Base64.strict_encode64("Ed#{key_id_binary_string}#{ed25519_public_key_binary_string}")
    end

    def assert_matching_key_ids!(key_id1, key_id2)
      raise "Signature key id is #{key_id1}\nbut the key id in the public key is #{key_id2}" unless key_id1 == key_id2
    end
  end
end
