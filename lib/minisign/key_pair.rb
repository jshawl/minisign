# frozen_string_literal: true

module Minisign
  # Generate a Minisign secret and public key
  class KeyPair
    include Minisign::Utils

    def initialize(password = nil)
      @password = password

      kd = key_data

      @checksum = blake2b256("Ed#{kd}")
      @keynum_sk = "#{kd}#{@checksum}"

      @kdf_salt = SecureRandom.bytes(32)
      @keynum_sk = xor(kdf_output, @keynum_sk.bytes).pack('C*') if @password
      @kdf_algorithm = password.nil? ? [0, 0].pack('U*') : 'Sc'
    end

    def private_key
      @kdf_opslimit = kdf_opslimit_bytes.pack('C*')
      @kdf_memlimit = kdf_memlimit_bytes.pack('C*')
      Minisign::PrivateKey.new(
        "untrusted comment: minisign secret key\n" +
        Base64.strict_encode64("Ed#{@kdf_algorithm}B2#{@kdf_salt}#{@kdf_opslimit}#{@kdf_memlimit}#{@keynum_sk}"),
        @password
      )
    end

    private

    def kdf_output
      derive_key(
        @password,
        @kdf_salt,
        kdf_opslimit_bytes.pack('V*').unpack('N*').sum,
        kdf_memlimit_bytes.pack('V*').unpack('N*').sum
      )
    end

    def key_data
      key_id = SecureRandom.bytes(8)
      signing_key = Ed25519::SigningKey.generate
      "#{key_id}#{signing_key.to_bytes}#{signing_key.verify_key.to_bytes}"
    end

    def kdf_opslimit_bytes
      [0, 0, 0, 2, 0, 0, 0, 0]
    end

    def kdf_memlimit_bytes
      [0, 0, 0, 64, 0, 0, 0, 0]
    end
  end
end
