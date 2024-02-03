# frozen_string_literal: true

module Minisign
  # Helpers used in multiple classes
  module Utils
    def blake2b512(message)
      OpenSSL::Digest.new('BLAKE2b512').digest(message)
    end
  end
end
