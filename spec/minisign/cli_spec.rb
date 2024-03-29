# frozen_string_literal: true

describe Minisign::CLI do
  describe '.usage' do
    it 'prints usage info and exits 1' do
      expect do
        Minisign::CLI.usage
      end.to raise_error(SystemExit)
    end
  end
  describe '.generate' do
    before do
      @options = {
        p: 'test/minisign.pub',
        s: 'test/minisign.key'
      }
      allow_any_instance_of(Minisign::KeyPair).to receive(:kdf_memlimit_bytes).and_return([0, 0, 0, 0, 0, 0, 0, 0])
      allow_any_instance_of(Minisign::KeyPair).to receive(:kdf_opslimit_bytes).and_return([0, 0, 0, 0, 0, 0, 0, 0])
    end
    it 'does not overwrite existing keys' do
      expect do
        Minisign::CLI.generate(@options)
      end.to raise_error(SystemExit)
    end
    it 'does not prompt for a password if -W' do
      keyname = SecureRandom.uuid
      options = {
        p: "test/generated/cli/#{keyname}.pub",
        s: "test/generated/cli/#{keyname}.key",
        W: true
      }
      expect(Minisign::CLI).not_to receive(:prompt)
      Minisign::CLI.generate(options)
    end
    it 'prints an error message if the passwords dont match' do
      password = SecureRandom.uuid
      password_confirmation = SecureRandom.uuid
      keyname = SecureRandom.uuid
      options = {
        p: "test/generated/cli/#{keyname}.pub",
        s: "test/generated/cli/#{keyname}.key"
      }
      allow(Minisign::CLI).to receive(:prompt).and_return(password, password_confirmation)
      expect do
        Minisign::CLI.generate(options)
      end.to raise_error(SystemExit)
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

    it 'changes the password for the private key without a password' do
      FileUtils.cp('test/unencrypted.key', 'test/generated/unencrypted.key')
      new_password = SecureRandom.uuid
      options = {
        s: 'test/generated/unencrypted.key'
      }
      allow(Minisign::CLI).to receive(:prompt).and_return(new_password)
      Minisign::CLI.change_password(options)
      expect do
        Minisign::PrivateKey.new(File.read(options[:s]), new_password)
      end.not_to raise_error
    end

    it 'removes the password for the private key' do
      allow(Minisign::CLI).to receive(:prompt).and_return(@old_password)
      Minisign::CLI.change_password(@options.merge({ W: true }))
      expect do
        Minisign::PrivateKey.new(File.read(@options[:s]))
      end.not_to raise_error
    end
  end

  describe '.sign' do
    it "doesn't prompt for a password if the key is unencrypted" do
      expect(Minisign::CLI).not_to receive(:prompt)
      options = {
        s: 'test/unencrypted.key',
        c: 'the untrusted comment',
        t: 'the trusted comment',
        m: 'test/generated/.keep'
      }
      # rubocop:disable Layout/LineLength
      command = "test/generated/minisign -Sm test/generated/.keep -s #{options[:s]} -c '#{options[:c]}' -t '#{options[:t]}'"
      # rubocop:enable Layout/LineLength
      system(command)
      jedisct1_signature = File.read('test/generated/.keep.minisig')
      File.delete('test/generated/.keep.minisig')
      Minisign::CLI.sign(options)
      signature = File.read('test/generated/.keep.minisig')
      expect(jedisct1_signature).to eq(signature)
    end
    it 'signs a file' do
      allow(Minisign::CLI).to receive(:prompt).and_return('password')
      options = {
        s: 'test/minisign.key',
        c: 'the untrusted comment',
        t: 'the trusted comment',
        m: 'test/generated/.keep'
      }
      system(
        # rubocop:disable Layout/LineLength
        "echo 'password' | test/generated/minisign -Sm #{options[:m]} -s #{options[:s]} -t '#{options[:t]}' -c '#{options[:c]}'"
        # rubocop:enable Layout/LineLength
      )
      jedisct1_signature = File.read('test/generated/.keep.minisig')
      File.delete('test/generated/.keep.minisig')
      Minisign::CLI.sign(options)
      signature = File.read('test/generated/.keep.minisig')
      expect(jedisct1_signature).to eq(signature)
    end
  end

  describe '.verify' do
    it 'verifies signatures' do
      options = {
        p: 'test/minisign.pub',
        m: 'test/generated/.keep'
      }
      expect do
        Minisign::CLI.verify(options)
      end.not_to raise_error
    end
    it 'prints an error message' do
      options = {
        p: 'test/minisign.pub',
        m: 'test/example.txt',
        x: 'test/example.txt.minisig.tampered'
      }
      expect do
        Minisign::CLI.verify(options)
      end.to raise_error(SystemExit)
    end
    it 'outputs the message' do
      options = {
        p: 'test/minisign.pub',
        m: 'test/example.txt',
        o: true
      }
      jedisct1 = "test/generated/minisign -Vom #{options[:m]} -p #{options[:p]}"
      ruby = "minisign -Vom #{options[:m]} -p #{options[:p]}"
      message = File.read(options[:m])
      expect(`#{ruby}`).to eq(message)
      expect(`#{ruby}`).to eq(`#{jedisct1}`)
    end
  end
end
