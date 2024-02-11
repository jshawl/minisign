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
    before do
      FileUtils.cp('test/minisign.key', 'test/generated/minisign.key')
      @options = {
        s: 'test/generated/minisign.key'
      }
      @old_password = 'password'
    end
    it 'changes the password for the private key' do
      new_password = SecureRandom.uuid
      allow(Minisign::CLI).to receive(:prompt).and_return(@old_password, new_password)
      Minisign::CLI.change_password(@options)
      expect do
        Minisign::PrivateKey.new(File.read(@options[:s]), new_password)
      end.not_to raise_error
    end

    it 'changes the password for the private key without a password'

    it 'removes the password for the private key' do
      allow(Minisign::CLI).to receive(:prompt).and_return(@old_password)
      Minisign::CLI.change_password(@options.merge({ W: true }))
      expect do
        Minisign::PrivateKey.new(File.read(@options[:s]))
      end.not_to raise_error
    end
  end

  describe '.sign' do
    it 'signs a file' do
      allow(Minisign::CLI).to receive(:prompt).and_return('password')
      options = {
        s: 'test/minisign.key',
        c: 'the untrusted comment',
        t: 'the trusted comment',
        m: 'test/generated/.keep'
      }
      system(
        "echo 'password' | test/generated/minisign -Sm test/generated/.keep -s test/minisign.key -t '#{options[:t]}'"
      )
      jedisct1_signature = File.read("test/generated/.keep.minisig")
      File.delete("test/generated/.keep.minisig")
      Minisign::CLI.sign(options)
      signature = File.read("test/generated/.keep.minisig")
      expect(jedisct1_signature).to eq(signature)
    end
  end
end
