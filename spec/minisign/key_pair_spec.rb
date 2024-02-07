# frozen_string_literal: true

describe Minisign::KeyPair do
  it 'generates a keypair without a password' do
    keypair = Minisign::KeyPair.new
    expect(keypair.private_key).to be_truthy
  end
  it 'generates a keypair with a password' do
    keypair = Minisign::KeyPair.new('secret password')
    expect(keypair.private_key).to be_truthy
    File.write("test/generated/new-keypair.key", keypair.private_key)
  end
end
