# frozen_string_literal: true

describe Minisign::KeyPair do
  it 'generates a keypair without a password' do
    keypair = Minisign::KeyPair.new
    expect(keypair.private_key).to be_truthy
    File.write('test/generated/new-unencrypted-keypair.key', keypair.private_key)
    File.write('test/generated/new-unencrypted-keypair.pub', keypair.public_key)
    expect(system(
             'test/generated/minisign -Sm test/generated/.keep -s test/generated/new-unencrypted-keypair.key'
           )).to be(true)
    expect(system(
             'test/generated/minisign -Vm test/generated/.keep -p test/generated/new-unencrypted-keypair.pub'
           )).to be(true)
  end
  it 'generates a keypair with a password' do
    keypair = Minisign::KeyPair.new('secret password')
    expect(keypair.private_key).to be_truthy
    File.write('test/generated/new-encrypted-keypair.key', keypair.private_key)
    File.write('test/generated/new-encrypted-keypair.pub', keypair.public_key)
    expect(system(
      # rubocop:disable Layout/LineLength
      "echo 'secret password' | test/generated/minisign -Sm test/generated/.keep -s test/generated/new-encrypted-keypair.key"
      # rubocop:enable Layout/LineLength
    )).to be(true)
    expect(system(
             'test/generated/minisign -Vm test/generated/.keep -p test/generated/new-encrypted-keypair.pub'
           )).to be(true)
  end
end
