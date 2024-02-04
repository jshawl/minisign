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
  end
end
