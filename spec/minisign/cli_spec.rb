# frozen_string_literal: true

describe Minisign::CLI do
  describe '.generate' do
    before do
      @options = {
        p: 'test/minisign.pub',
        s: 'test/minisign.key'
      }
    end
    it 'does not overwrite existing keys' do
      expect do
        Minisign::CLI.generate(@options)
      end.to raise_error(SystemExit)
    end
    it 'does not prompt for a password if -W' do
      keyname = SecureRandom.uuid
      SecureRandom.uuid
      options = {
        p: "test/generated/cli/#{keyname}.pub",
        s: "test/generated/cli/#{keyname}.key",
        W: true
      }
      expect(Minisign::CLI).not_to receive(:prompt)
      Minisign::CLI.generate(options)
    end
    it 'writes the key files' do
      keyname = SecureRandom.uuid
      password = SecureRandom.uuid
      options = {
        p: "test/generated/cli/#{keyname}.pub",
        s: "test/generated/cli/#{keyname}.key"
      }
      allow(Minisign::CLI).to receive(:prompt).and_return(password)
      Minisign::CLI.generate(options)
      expect(File.exist?(options[:p])).to eq(true)
      expect(File.exist?(options[:p])).to eq(true)
    end
  end
end
