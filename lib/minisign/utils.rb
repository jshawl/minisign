# frozen_string_literal: true

module Minisign
  # Helpers used in multiple classes
  module Utils
    def blake2b256(message)
      RbNaCl::Hash::Blake2b.digest(message, { digest_size: 32 })
    end

    def blake2b512(message)
      RbNaCl::Hash::Blake2b.digest(message, { digest_size: 64 })
    end

    # @return [Array<32 bit unsigned ints>]
    def xor(kdf_output, contents)
      kdf_output.each_with_index.map do |b, i|
        contents[i] ^ b
      end
    end

    # @return [String] bytes as little endian hexadecimal
    def hex(bytes)
      bytes.map { |c| c.to_s(16) }.reverse.join.upcase
    end

    # @return [String] the <kdf_output> used to xor the ed25519 keys
    def derive_key(password, kdf_salt, kdf_opslimit, kdf_memlimit)
      RbNaCl::PasswordHash.scrypt(
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        104
      ).bytes
    end
  end
end
