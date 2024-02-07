# frozen_string_literal: true

describe Minisign::Signature do
  before do
    @signature = Minisign::Signature.new(File.read('test/example.txt.minisig'))
  end

  it 'has a key id' do
    expect(@signature.key_id).to eq('4CB7A94FABA329A6')
  end

  it 'can be written to a file' do
    expect(@signature.to_s).to eq(File.read('test/example.txt.minisig'))
  end
end
