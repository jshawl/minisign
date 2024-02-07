# frozen_string_literal: true

module Minisign
  # Generate a Minisign secret and public key
  class KeyPair
    include Minisign::Utils

    def initialize(password = nil)
      @password = password
      @key_id = SecureRandom.bytes(8)
      @signing_key = Ed25519::SigningKey.generate
      kd = key_data

      @checksum = blake2b256("Ed#{kd}")
      @keynum_sk = "#{kd}#{@checksum}"

      @kdf_salt = SecureRandom.bytes(32)
      @keynum_sk = xor(kdf_output, @keynum_sk.bytes).pack('C*') if @password
      @kdf_algorithm = password.nil? ? [0, 0].pack('U*') : 'Sc'
    end

    # @return [Minisign::PrivateKey]
    def private_key
      @kdf_opslimit = kdf_opslimit_bytes.pack('C*')
      @kdf_memlimit = kdf_memlimit_bytes.pack('C*')
      data = "Ed#{@kdf_algorithm}B2#{@kdf_salt}#{@kdf_opslimit}#{@kdf_memlimit}#{@keynum_sk}"
      Minisign::PrivateKey.new(
        "untrusted comment: minisign secret key\n#{Base64.strict_encode64(data)}",
        @password
      )
    end

    # @return [Minisign::PublicKey]
    def public_key
      data = Base64.strict_encode64("Ed#{@key_id}#{@signing_key.verify_key.to_bytes}")
      Minisign::PublicKey.new(data)
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
      "#{@key_id}#{@signing_key.to_bytes}#{@signing_key.verify_key.to_bytes}"
    end

    # 🤷
    # https://github.com/RubyCrypto/rbnacl/blob/3e8d8f8822e2b8eeba215e6be027e8ee210edfb9/lib/rbnacl/password_hash/scrypt.rb#L33-L34
    def kdf_opslimit_bytes
      [0, 0, 0, 2, 0, 0, 0, 0]
    end

    def kdf_memlimit_bytes
      [0, 0, 0, 64, 0, 0, 0, 0]
    end
  end
end
