# frozen_string_literal: true

describe Minisign::PrivateKey do
  before(:all) do
    @private_key = Minisign::PrivateKey.new(File.read('test/minisign.key'), 'password')
  end

  describe '.new' do
    it 'parses the signature_algorithm' do
      expect(@private_key.send(:signature_algorithm)).to eq('Ed')
    end

    it 'parses the kdf_algorithm' do
      expect(@private_key.send(:kdf_algorithm)).to eq('Sc')
    end

    it 'parses the kdf_algorithm' do
      @unencrypted_private_key = Minisign::PrivateKey.new(File.read('test/unencrypted.key'))
      expect(@unencrypted_private_key.send(:kdf_algorithm).unpack('C*')).to eq([0, 0])
    end

    it 'raises if the private key requires a password but is not supplied' do
      expect do
        Minisign::PrivateKey.new(File.read('test/minisign.key'))
      end.to raise_error(Minisign::PasswordMissingError, 'Missing password for encrypted key')
    end

    it 'raises if the password is incorrect for the private key' do
      expect do
        Minisign::PrivateKey.new(File.read('test/minisign.key'), 'not the right password')
      end.to raise_error(Minisign::PasswordIncorrectError, 'Wrong password for that key')
    end

    it 'parses the cksum_algorithm' do
      expect(@private_key.send(:cksum_algorithm)).to eq('B2')
    end

    it 'parses the kdf_salt' do
      kdf_salt = @private_key.instance_variable_get('@kdf_salt')
      expect(kdf_salt).to eq([17, 255, 178, 97, 174, 94, 1, 125, 252, 62, 7, 107, 35, 116, 204, 199, 12,
                              190, 222, 200, 51, 166, 7, 25, 89, 5, 225, 56, 170, 157, 127, 219])
    end

    it 'parses the key id' do
      expect(@private_key.key_id).to eq([166, 41, 163, 171, 79, 169, 183, 76])
    end

    it 'parses the public key' do
      key = @private_key.instance_variable_get('@ed25519_public_key_bytes')
      expect(key).to eq([108, 35, 192, 26, 47, 128, 233, 165, 133, 38, 242, 5, 76, 55, 135, 40,
                         103, 72, 230, 43, 184, 117, 219, 37, 173, 250, 196, 122, 252, 174, 173, 140])
    end

    it 'parses the secret key' do
      key = @private_key.instance_variable_get('@ed25519_private_key_bytes')
      expect(key).to eq([65, 87, 110, 33, 168, 130, 118, 100, 249, 200, 160, 167, 47, 59, 141,
                         122, 156, 38, 80, 199, 139, 1, 21, 18, 116, 110, 204, 131, 199, 202, 181, 87])
    end

    it 'parses the checksum' do
      checksum = @private_key.instance_variable_get('@checksum')
      expect(checksum).to eq([19, 146, 239, 121, 33, 164, 216, 219, 8, 104, 111, 52, 198, 78, 21, 236,
                              113, 255, 174, 47, 39, 216, 61, 198, 233, 161, 233, 143, 84, 246, 255, 150])
    end

    it 'can be written to a file' do
      expect(@private_key.to_s).to eq(File.read('test/minisign.key'))
    end

    it 'can recreate the public key from the private key' do
      # remove the custom untrusted comment
      original = File.read('test/minisign.pub').gsub(' yay', '')
      expect(@private_key.public_key.to_s).to eq(original)
    end
  end

  describe 'sign' do
    it 'signs a file' do
      @filename = 'encrypted-key.txt'
      @message = SecureRandom.uuid
      trusted_comment = 'this is a trusted comment'
      untrusted_comment = 'this is an untrusted comment'
      signature = @private_key.sign(@filename, @message, trusted_comment, untrusted_comment)
      expect(signature.to_s).to match(trusted_comment)
      expect(signature.to_s).to match(untrusted_comment)
      @public_key = Minisign::PublicKey.new('RWSmKaOrT6m3TGwjwBovgOmlhSbyBUw3hyhnSOYruHXbJa36xHr8rq2M')
      expect(@public_key.verify(signature, @message)).to match('Signature and comment signature verified')
      File.write("test/generated/#{@filename}", @message)
      File.write("test/generated/#{@filename}.minisig", signature)
      expect(system('test/generated/minisign -Vm test/generated/encrypted-key.txt -p test/minisign.pub')).to be(true)
    end
    it 'signs a file with an unencrypted key' do
      @filename = 'unencrypted-key.txt'
      @message = SecureRandom.uuid
      @unencrypted_private_key = Minisign::PrivateKey.new(File.read('test/unencrypted.key'))
      signature = @unencrypted_private_key.sign(@filename, @message)
      @public_key = Minisign::PublicKey.new('RWT/N/MXaBIWRAPzfdEKqVRq9txskjf5qh7EbqMLVHjkNTGFazO3zMw2')
      expect(@public_key.verify(signature, @message)).to match('Signature and comment signature verified')
      File.write("test/generated/#{@filename}", @message)
      File.write("test/generated/#{@filename}.minisig", signature)
      expect(system(
               'test/generated/minisign -Vm test/generated/unencrypted-key.txt -p test/unencrypted.pub'
             )).to be(true)
    end
  end

  describe '#change_password!' do
    before do
      @private_key = Minisign::PrivateKey.new(File.read('test/minisign.key'), 'password')
    end
    it 'changes the password' do
      random_trusted_comment = SecureRandom.uuid
      new_password = SecureRandom.uuid
      original_public_key = @private_key.public_key
      original_signature = @private_key.sign('example.txt', 'example', random_trusted_comment)
      original_private_key = @private_key.to_s
      @private_key.change_password! new_password
      new_signature = @private_key.sign('example.txt', 'example', random_trusted_comment)
      expect(original_signature.to_s).to eq(new_signature.to_s)
      expect(original_public_key.to_s).to eq(@private_key.public_key.to_s)
      expect(original_private_key.to_s).not_to eq(@private_key.to_s)
      expect do
        Minisign::PrivateKey.new(@private_key.to_s, new_password)
      end.not_to raise_error
      expect do
        Minisign::PrivateKey.new(@private_key.to_s)
      end.to raise_error(Minisign::PasswordMissingError, 'Missing password for encrypted key')

      File.write('test/generated/new-password.key', @private_key)
      path = 'test/generated'
      command = "echo #{new_password} | #{path}/minisign -Sm #{path}/.keep -s #{path}/new-password.key"
      expect(system(command)).to be(true)
    end

    it 'removes the password if nil' do
      @private_key.change_password! nil
      expect do
        Minisign::PrivateKey.new(@private_key.to_s)
      end.not_to raise_error
      File.write('test/generated/removed-password.key', @private_key)
      path = 'test/generated'
      # does not prompt for password
      command = "#{path}/minisign -Sm #{path}/.keep -s #{path}/removed-password.key"
      expect(system(command)).to be(true)
    end
  end
end
