# frozen_string_literal: true

module Minisign
  # A module that invokes RbNaCl with user-focused actionable error messages.
  module NaCl
    def self.assert_libsodium_dependency_met!
      return if RbNaCl.const_defined?(:PasswordHash)

      raise Minisign::LibSodiumDependencyError, 'libsodium is not installed!'
    end

    module Hash
      # see RbNaCl::Hash::Blake2b
      module Blake2b
        def self.digest(*args)
          NaCl.assert_libsodium_dependency_met!
          RbNaCl::Hash::Blake2b.digest(*args)
        end
      end
    end

    # see RbNaCl::PasswordHash
    module PasswordHash
      def self.scrypt(*args)
        NaCl.assert_libsodium_dependency_met!
        RbNaCl::PasswordHash.scrypt(*args)
      end
    end
  end
end
