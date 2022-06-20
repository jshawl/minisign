# frozen_string_literal: true

describe Minisign::PublicKey do
  before do
    @pk = Minisign::PublicKey.new(File.read('test/local.pub').split("\n").pop)
    @message = File.read('test/example.txt')
  end
  it 'verifies signatures' do
    @signature = Minisign::Signature.new(File.read('test/example.txt.minisig'))
    expect(@pk.verify(@signature, @message)).to match('Trusted comment')
  end
  it 'raises ed25519 errors' do
    @signature = Minisign::Signature.new(File.read('test/example.txt.minisig.unverifiable'))
    expect { @pk.verify(@signature, @message) }.to raise_error(Ed25519::VerifyError)
  end
  it 'verifies trusted comments' do
    @signature = Minisign::Signature.new(File.read('test/example.txt.minisig.tampered'))
    expect { @pk.verify(@signature, @message) }.to raise_error('Comment signature verification failed')
  end
  xit 'has a key_id' do
    expect(@pk.key_id).to eq('abc')
  end
  xit 'raises errors on key id mismatch' do
    @pk = Minisign::PublicKey.new('RWQIoBiLxWlf8dGe/DM+igVgetlwOuhWW3abyI1z8eS1RHJVc4o+1sCI')
    @signature = Minisign::Signature.new(File.read('test/example.txt.minisig'))
    expect { @pk.verify(@signature, @message) }.to raise_error('Signature key id in test/example.txt.minisig is E86FECED695E8E0
but the key id in the public key is F15F69C58B18A008')
  end
end

describe Minisign::Signature do
  it 'has a key id' do
    @signature = Minisign::Signature.new(File.read('test/example.txt.minisig'))
    expect(@signature.key_id).to eq('E86FECED695E8E0')
  end
end
