# frozen_string_literal: true

module Minisign
  # Parse ed25519 signing key from minisign private key
  class PrivateKey
    attr_reader :signature_algorithm, :kdf_algorithm, :cksum_algorithm, :kdf_salt, :kdf_opslimit, :kdf_memlimit,
                :key_id, :public_key, :secret_key, :checksum

    # rubocop:disable Metrics/AbcSize
    def initialize(str, password = nil)
      contents = str.split("\n")
      bytes = Base64.decode64(contents.last).bytes
      @signature_algorithm, @kdf_algorithm, @cksum_algorithm =
        [bytes[0..1], bytes[2..3], bytes[4..5]].map { |a| a.pack('U*') }
      @kdf_salt = bytes[6..37]
      @kdf_opslimit = bytes[38..45].pack('V*').unpack('N*').sum
      @kdf_memlimit = bytes[46..53].pack('V*').unpack('N*').sum
      kdf_output = derive_key(password, @kdf_salt, @kdf_opslimit, @kdf_memlimit)
      @key_id, @secret_key, @public_key, @checksum = xor(kdf_output, bytes[54..157])
    end
    # rubocop:enable Metrics/AbcSize

    def derive_key(password, kdf_salt, kdf_opslimit, kdf_memlimit)
      RbNaCl::PasswordHash.scrypt(
        password,
        kdf_salt.pack('C*'),
        kdf_opslimit,
        kdf_memlimit,
        104
      ).bytes
    end

    def xor(kdf_output, contents)
      xored = kdf_output.each_with_index.map do |b, i|
        contents[i] ^ b
      end
      [xored[0..7], xored[8..39], xored[40..71], xored[72..103]]
    end

    def ed25519_signing_key
      Ed25519::SigningKey.new(@secret_key.pack('C*'))
    end

    def blake2b512(message)
      OpenSSL::Digest.new('BLAKE2b512').digest(message)
    end

    def sign(filename, message)
      signature = ed25519_signing_key.sign(blake2b512(message))
      trusted_comment = "timestamp:#{Time.now.to_i}\tfile:#{filename}\thashed"
      global_signature = ed25519_signing_key.sign("#{signature}#{trusted_comment}")
      [
        'untrusted comment: <arbitrary text>',
        Base64.strict_encode64("ED#{@key_id.pack('C*')}#{signature}"),
        "trusted comment: #{trusted_comment}",
        Base64.strict_encode64(global_signature),
        ''
      ].join("\n")
    end
  end
end
