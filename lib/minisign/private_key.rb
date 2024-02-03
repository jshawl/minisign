# frozen_string_literal: true

module Minisign
  class PrivateKey
    attr_reader :signature_algorithm, :kdf_algorithm, :cksum_algorithm, :kdf_salt, :kdf_opslimit, :kdf_memlimit,
                :key_id, :public_key, :secret_key, :checksum

    def initialize(opts, _password = nil)
      @signature_algorithm = opts[:signature_algorithm]
      @kdf_algorithm = opts[:kdf_algorithm]
      @cksum_algorithm = opts[:cksum_algorithm]
      @kdf_salt = opts[:kdf_salt]
      @kdf_opslimit = opts[:kdf_opslimit]
      @kdf_memlimit = opts[:kdf_memlimit]
      @key_id = opts[:key_id]
      @secret_key = opts[:secret_key]
      @public_key = opts[:public_key]
      @checksum = opts[:checksum]
    end

    def self.from_file(path, password = nil)
      contents = File.read(path).split("\n")
      bytes = Base64.decode64(contents.last).bytes
      signature_algorithm = bytes[0..1].pack('U*')
      kdf_algorithm = bytes[2..3].pack('U*')
      cksum_algorithm = bytes[4..5].pack('U*')
      kdf_salt = bytes[6..37]
      kdf_opslimit = bytes[38..45].pack('V*').unpack('N*').sum
      kdf_memlimit = bytes[46..53].pack('V*').unpack('N*').sum

      kdf_output = RbNaCl::PasswordHash.scrypt(
        password,
        kdf_salt.pack('C*'),
        kdf_opslimit,
        kdf_memlimit,
        104
      ).bytes

      xored = kdf_output.each_with_index.map do |b, i|
        bytes[54..157][i] ^ b
      end

      key_id = xored[0..7]
      secret_key = xored[8..39]
      public_key = xored[40..71]
      checksum = xored[72..103]

      new({
            signature_algorithm: signature_algorithm,
            kdf_algorithm: kdf_algorithm,
            cksum_algorithm: cksum_algorithm,
            kdf_salt: kdf_salt,
            kdf_opslimit: kdf_opslimit,
            kdf_memlimit: kdf_memlimit,
            key_id: key_id,
            secret_key: secret_key,
            public_key: public_key,
            checksum: checksum
          })
    end
  end
end
