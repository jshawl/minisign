# frozen_string_literal: true

module Minisign
  class SignatureVerificationError < StandardError
  end

  class PasswordMissingError < StandardError
  end

  class PasswordIncorrectError < StandardError
  end

  class LibSodiumDependencyError < StandardError
  end
end
