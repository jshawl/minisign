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

  describe '.recreate' do
    it 'recreates the public key from a private key' do
      keyname = SecureRandom.uuid
      options = {
        p: "test/generated/#{keyname}.pub",
        s: 'test/minisign.key'
      }
      allow(Minisign::CLI).to receive(:prompt).and_return('password')
      Minisign::CLI.recreate(options)
      new_public_key = File.read(options[:p])
      existing_public_key = File.read('test/minisign.pub').gsub(' yay', '')
      expect(new_public_key).to eq(existing_public_key)
    end
  end

  describe '.change_password' do
    it 'changes the password for the private key' do
      FileUtils.cp("test/minisign.key", "test/generated/minisign.key")
      options = {
        s: "test/generated/minisign.key"
      }
      old_password = 'password'
      new_password = SecureRandom.uuid
      allow(Minisign::CLI).to receive(:prompt).and_return(old_password, new_password)
      Minisign::CLI.change_password(options)
      expect {
        Minisign::PrivateKey.new(File.read(options[:s]), new_password)
      }.not_to raise_error
    end
  end
end
