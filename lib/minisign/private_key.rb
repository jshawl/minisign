# frozen_string_literal: true

module Minisign
  # Parse ed25519 signing key from minisign private key
  class PrivateKey
    include Utils
    attr_reader :signature_algorithm, :kdf_algorithm, :cksum_algorithm, :kdf_salt, :kdf_opslimit, :kdf_memlimit,
                :key_id, :public_key, :secret_key, :checksum

    # rubocop:disable Metrics/AbcSize
    # rubocop:disable Layout/LineLength
    # rubocop:disable Metrics/MethodLength

    # Parse signing information from the minisign private key
    #
    # @param str [String] The minisign private key
    # @example
    #   Minisign::PrivateKey.new('RWRTY0IyEf+yYa5eAX38PgdrI3TMxwy+3sgzpgcZWQXhOKqdf9sAAAACAAAAAAAAAEAAAAAAHe8Olzttgk6k5pZyT3CyCTcTAV0bLN3kq5CUqhLjqSdYZ6oEWs/S7ztaephS+/jwnuOElLBKkg3Sd56jzyvMwL4qStNUTyPDqckNjniw2SlowmHN8n5NnR47gvqjo96E+vakpw8v5PE=', 'password')
    def initialize(str, password = nil)
      contents = str.split("\n")
      bytes = Base64.decode64(contents.last).bytes
      @signature_algorithm, @kdf_algorithm, @cksum_algorithm =
        [bytes[0..1], bytes[2..3], bytes[4..5]].map { |a| a.pack('U*') }
      raise 'Missing password for encrypted key' if @kdf_algorithm.bytes.sum != 0 && password.nil?

      @kdf_salt = bytes[6..37]
      @kdf_opslimit = bytes[38..45].pack('V*').unpack('N*').sum
      @kdf_memlimit = bytes[46..53].pack('V*').unpack('N*').sum
      @key_data_bytes = if password
                          kdf_output = derive_key(password, @kdf_salt, @kdf_opslimit, @kdf_memlimit)
                          xor(kdf_output, bytes[54..157])
                        else
                          bytes[54..157]
                        end
      @key_id, @secret_key, @public_key, @checksum = key_data(@key_data_bytes)
      assert_keypair_match!
    end
    # rubocop:enable Layout/LineLength
    # rubocop:enable Metrics/AbcSize
    # rubocop:enable Metrics/MethodLength

    def assert_keypair_match!
      raise 'Wrong password for that key' if @public_key != ed25519_signing_key.verify_key.to_bytes.bytes
    end

    def key_data(bytes)
      [bytes[0..7], bytes[8..39], bytes[40..71], bytes[72..103]]
    end

    # @return [String] the <kdf_output> used to xor the ed25519 keys
    def derive_key(password, kdf_salt, kdf_opslimit, kdf_memlimit)
      RbNaCl::PasswordHash.scrypt(
        password,
        kdf_salt.pack('C*'),
        kdf_opslimit,
        kdf_memlimit,
        104
      ).bytes
    end

    # rubocop:disable Layout/LineLength

    # @return [Array<32 bit unsigned ints>] the byte array containing the key id, the secret and public ed25519 keys, and the checksum
    def xor(kdf_output, contents)
      # rubocop:enable Layout/LineLength
      kdf_output.each_with_index.map do |b, i|
        contents[i] ^ b
      end
    end

    # @return [Ed25519::SigningKey] the ed25519 signing key
    def ed25519_signing_key
      Ed25519::SigningKey.new(@secret_key.pack('C*'))
    end

    # Sign a file/message
    #
    # @param filename [String] The filename to be used in the trusted comment section
    # @param message [String] The file's contents
    # @param comment [String] An optional trusted comment to be included in the signature
    # @return [String] the signature in the .minisig format that can be written to a file.
    def sign(filename, message, comment = nil)
      signature = ed25519_signing_key.sign(blake2b512(message))
      trusted_comment = comment || "timestamp:#{Time.now.to_i}\tfile:#{filename}\thashed"
      global_signature = ed25519_signing_key.sign("#{signature}#{trusted_comment}")
      [
        'untrusted comment: <arbitrary text>',
        Base64.strict_encode64("ED#{@key_id.pack('C*')}#{signature}"),
        "trusted comment: #{trusted_comment}",
        Base64.strict_encode64(global_signature),
        ''
      ].join("\n")
    end

    def to_s
      kdf_algorithm = @password.nil? ? [0, 0].pack('U*') : 'Sc'
      kdf_salt = @kdf_salt.pack('C*')
      kdf_opslimit = [@kdf_opslimit, 0].pack('L*')
      kdf_memlimit = [@kdf_memlimit, 0].pack('L*')
      data = "Ed#{kdf_algorithm}B2#{kdf_algorithm}#{kdf_salt}#{kdf_opslimit}#{kdf_memlimit}#{@key_data_bytes}"
      "untrusted comment: <arbitrary text>\n#{Base64.strict_encode64(data)}\n"
    end
  end
end
