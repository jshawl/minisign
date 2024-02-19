# frozen_string_literal: true

require 'ed25519'
require 'base64'
require 'openssl'
begin
  require 'rbnacl'
rescue LoadError
  # errors handled when invoked (see Minisign::NaCl)
end

require 'minisign/cli'
require 'minisign/utils'
require 'minisign/public_key'
require 'minisign/signature'
require 'minisign/private_key'
require 'minisign/key_pair'
require 'minisign/nacl'
require 'minisign/error'
