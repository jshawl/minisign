# frozen_string_literal: true

describe Minisign::NaCl do
  it 'raises LibSodiumDependencyError if libsodium not installed' do
    hash = RbNaCl.send(:remove_const, :Hash)
    password_hash = RbNaCl.send(:remove_const, :PasswordHash)
    expect do
      Minisign::NaCl::Hash::Blake2b.digest('message', { digest_size: 32 })
    end.to raise_error(Minisign::LibSodiumDependencyError)
    RbNaCl.const_set(:Hash, hash)
    RbNaCl.const_set(:PasswordHash, password_hash)
  end
end
