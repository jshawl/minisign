# frozen_string_literal: true

module Minisign
  # Parse ed25519 signing key from minisign private key
  class PrivateKey
    include Utils
    attr_reader :kdf_salt, :kdf_opslimit, :kdf_memlimit,
                :key_id, :ed25519_public_key_bytes, :ed25519_private_key_bytes, :checksum

    # Parse signing information from the minisign private key
    #
    # @param str [String] The minisign private key
    # @param password [String] The password used to encrypt the private key
    # @example
    #   Minisign::PrivateKey.new(
    #     File.read("test/minisign.key")
    #     'password'
    #   )
    def initialize(str, password = nil)
      comment, data = str.split("\n")
      @password = password
      decoded = Base64.decode64(data)
      @untrusted_comment = comment.split('untrusted comment: ').last
      @bytes = decoded.bytes
      @kdf_salt, @kdf_opslimit, @kdf_memlimit = scrypt_params(@bytes)
      @key_id, @ed25519_private_key_bytes, @ed25519_public_key_bytes, @checksum = key_data(password, @bytes[54..157])
      assert_valid_key!
    end

    # @return [Minisign::PublicKey]
    def public_key
      data = Base64.strict_encode64("Ed#{@key_id.pack('C*')}#{@ed25519_public_key_bytes.pack('C*')}")
      Minisign::PublicKey.new(data)
    end

    # Sign a file/message
    #
    # @param filename [String] The filename to be used in the trusted comment section
    # @param message [String] The file's contents
    # @param comment [String] An optional trusted comment to be included in the signature
    # @return [Minisign::Signature]
    def sign(filename, message, comment = nil)
      signature = ed25519_signing_key.sign(blake2b512(message))
      trusted_comment = comment || "timestamp:#{Time.now.to_i}\tfile:#{filename}\thashed"
      global_signature = ed25519_signing_key.sign("#{signature}#{trusted_comment}")
      Minisign::Signature.new([
        'untrusted comment: <arbitrary text>',
        Base64.strict_encode64("ED#{@key_id.pack('C*')}#{signature}"),
        "trusted comment: #{trusted_comment}",
        Base64.strict_encode64(global_signature),
        ''
      ].join("\n"))
    end

    # @return [String] A string in the minisign.pub format
    def to_s
      kdf_salt = @kdf_salt.pack('C*')
      kdf_opslimit = [@kdf_opslimit, 0].pack('L*')
      kdf_memlimit = [@kdf_memlimit, 0].pack('L*')
      keynum_sk = key_data(@password,
                           @key_id + @ed25519_private_key_bytes + @ed25519_public_key_bytes + @checksum).flatten
      data = "Ed#{kdf_algorithm}B2#{kdf_salt}#{kdf_opslimit}#{kdf_memlimit}#{keynum_sk.pack('C*')}"
      "untrusted comment: #{@untrusted_comment}\n#{Base64.strict_encode64(data)}\n"
    end

    private

    def signature_algorithm
      @bytes[0..1].pack('U*')
    end

    def cksum_algorithm
      @bytes[4..5].pack('U*')
    end

    def kdf_algorithm
      @bytes[2..3].pack('U*')
    end

    def scrypt_params(bytes)
      [bytes[6..37], bytes[38..45].pack('V*').unpack('N*').sum, bytes[46..53].pack('V*').unpack('N*').sum]
    end

    # @raise [RuntimeError] if the extracted public key does not match the derived public key
    def assert_valid_key!
      raise 'Missing password for encrypted key' if kdf_algorithm.bytes.sum != 0 && @password.nil?
      raise 'Wrong password for that key' if @ed25519_public_key_bytes != ed25519_signing_key.verify_key.to_bytes.bytes
    end

    def key_data(password, bytes)
      if password
        kdf_output = derive_key(password, @kdf_salt.pack('C*'), @kdf_opslimit, @kdf_memlimit)
        bytes = xor(kdf_output, bytes)
      end
      [bytes[0..7], bytes[8..39], bytes[40..71], bytes[72..103]]
    end

    # @return [Ed25519::SigningKey] the ed25519 signing key
    def ed25519_signing_key
      Ed25519::SigningKey.new(@ed25519_private_key_bytes.pack('C*'))
    end
  end
end
