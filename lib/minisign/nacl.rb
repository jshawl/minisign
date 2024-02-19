# frozen_string_literal: true

module Minisign
  # A module that invokes RbNaCl with user-focused actionable error messages.
  module NaCl
    def self.safely
      yield
    rescue NameError
      raise Minisign::LibSodiumDependencyError, 'libsodium is not installed!'
    end

    module Hash
      # see RbNaCl::Hash::Blake2b
      module Blake2b
        def self.digest(*args)
          NaCl.safely do
            RbNaCl::Hash::Blake2b.digest(*args)
          end
        end
      end
    end

    # see RbNaCl::PasswordHash
    module PasswordHash
      def self.scrypt(*args)
        NaCl.safely do
          RbNaCl::PasswordHash.scrypt(*args)
        end
      end
    end
  end
end
