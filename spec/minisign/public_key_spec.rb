# frozen_string_literal: true

describe Minisign::PublicKey do
  before do
    @pk = Minisign::PublicKey.new(File.read('test/minisign.pub'))
    @message = File.read('test/example.txt')
  end
  it 'verifies signatures' do
    @signature = Minisign::Signature.new(File.read('test/example.txt.minisig'))
    expect(@pk.verify(@signature, @message)).to match('Trusted comment')
  end
  it 'raises ed25519 errors for valid signatures but mismatching content' do
    @signature = Minisign::Signature.new(File.read('test/example.txt.minisig.unverifiable'))
    expect do
      @pk.verify(@signature, @message)
    end.to raise_error(Minisign::SignatureVerificationError, 'Signature verification failed')
  end
  it 'verifies trusted comments' do
    @signature = Minisign::Signature.new(File.read('test/example.txt.minisig.tampered'))
    expect do
      @pk.verify(@signature,
                 @message)
    end.to raise_error(Minisign::SignatureVerificationError, 'Comment signature verification failed')
  end
  it 'has a key_id' do
    expect(@pk.key_id).to eq('4CB7A94FABA329A6')
  end
  it 'raises errors on key id mismatch' do
    @pk = Minisign::PublicKey.new('RWQIoBiLxWlf8dGe/DM+igVgetlwOuhWW3abyI1z8eS1RHJVc4o+1sCI')
    @signature = Minisign::Signature.new(File.read('test/example.txt.minisig'))
    expect do
      @pk.verify(@signature, @message)
    end.to raise_error(Minisign::SignatureVerificationError,
                       "Signature key id is 4CB7A94FABA329A6\nbut the key id in the public key is F15F69C58B18A08")
  end
  it 'can be written to a file' do
    expect(@pk.to_s).to eq(File.read('test/minisign.pub'))
  end
  it 'regenerates an untrusted comment if not provided' do
    @pk = Minisign::PublicKey.new('RWSmKaOrT6m3TGwjwBovgOmlhSbyBUw3hyhnSOYruHXbJa36xHr8rq2M')
    expect(@pk.to_s).to match('minisign public key 4CB7A94FABA329A6')
  end
end
