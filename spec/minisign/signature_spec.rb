# frozen_string_literal: true

describe Minisign::Signature do
  it 'has a key id' do
    @signature = Minisign::Signature.new(File.read('test/example.txt.minisig'))
    expect(@signature.key_id).to eq('4CB7A94FABA329A6')
  end
end
