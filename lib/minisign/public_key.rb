# frozen_string_literal: true

module Minisign
  # The public key used to verify signatures
  class PublicKey
    include Utils
    # Read a minisign public key
    #
    # @param str [String] The minisign public key
    # @example
    #   Minisign::PublicKey.new('RWTg6JXWzv6GDtDphRQ/x7eg0LaWBcTxPZ7i49xEeiqXVcR+r79OZRWM')
    #   # or from a file:
    #   Minisign::PublicKey.new(File.read('test/minisign.pub'))
    def initialize(str)
      @lines = str.split("\n")
      @decoded = Base64.strict_decode64(@lines.last)
    end

    # @return [String] the key id
    # @example
    #   public_key.key_id
    #   #=> "E86FECED695E8E0"
    def key_id
      key_id_binary_string.bytes.map { |c| c.to_s(16) }.reverse.join.upcase
    end

    # Verify a message's signature
    #
    # @param signature [Minisign::Signature]
    # @param message [String] the content that was signed
    # @return [String] the trusted comment
    # @raise Ed25519::VerifyError on invalid signatures
    # @raise RuntimeError on tampered trusted comments
    # @raise RuntimeError on mismatching key ids
    def verify(signature, message)
      assert_matching_key_ids!(signature.key_id, key_id)
      verify_message_signature(signature.signature, message)
      verify_comment_signature(signature.trusted_comment_signature, signature.signature + signature.trusted_comment)
      "Signature and comment signature verified\nTrusted comment: #{signature.trusted_comment}"
    end

    # @return [String] The public key that can be written to a file
    def to_s
      "untrusted comment: #{untrusted_comment}\n#{key_data}\n"
    end

    private

    def verify_comment_signature(signature, comment)
      ed25519_verify_key.verify(signature, comment)
    rescue Ed25519::VerifyError
      raise Minisign::SignatureVerificationError, 'Comment signature verification failed'
    end

    def verify_message_signature(signature, message)
      ed25519_verify_key.verify(signature, blake2b512(message))
    rescue Ed25519::VerifyError => e
      raise Minisign::SignatureVerificationError, e
    end

    def untrusted_comment
      if @lines.length == 1
        "minisign public key #{key_id}"
      else
        @lines.first.split('untrusted comment: ').last
      end
    end

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
      return if key_id1 == key_id2

      raise Minisign::SignatureVerificationError,
            "Signature key id is #{key_id1}\nbut the key id in the public key is #{key_id2}"
    end
  end
end
