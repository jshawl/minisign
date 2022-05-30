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
end
