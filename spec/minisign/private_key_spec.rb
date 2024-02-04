# frozen_string_literal: true

describe Minisign::PrivateKey do
  before(:all) do
    @private_key = Minisign::PrivateKey.new(File.read('test/minisign.key'), 'password')
  end

  describe '.new' do
    it 'parses the signature_algorithm' do
      expect(@private_key.signature_algorithm).to eq('Ed')
    end

    it 'parses the kdf_algorithm' do
      expect(@private_key.kdf_algorithm).to eq('Sc')
    end

    it 'raises if the private key requires a password but is not supplied' do
      expect do
        Minisign::PrivateKey.new(File.read('test/minisign.key'))
      end.to raise_error('Missing password for encrypted key')
    end

    it 'raises if the password is incorrect for the private key' do
      expect do
        Minisign::PrivateKey.new(File.read('test/minisign.key'), 'not the right password')
      end.to raise_error('Wrong password for that key')
    end

    it 'parses the cksum_algorithm' do
      expect(@private_key.cksum_algorithm).to eq('B2')
    end

    it 'parses the kdf_salt' do
      expect(@private_key.kdf_salt).to eq([17, 255, 178, 97, 174, 94, 1, 125, 252, 62, 7, 107, 35, 116, 204, 199, 12,
                                           190, 222, 200, 51, 166, 7, 25, 89, 5, 225, 56, 170, 157, 127, 219])
    end

    it 'parses the kdf_opslimit' do
      expect(@private_key.kdf_opslimit).to eq(33_554_432)
    end

    it 'parses the kdf_memlimit' do
      expect(@private_key.kdf_memlimit).to eq(1_073_741_824)
    end

    it 'parses the key id' do
      expect(@private_key.key_id).to eq([166, 41, 163, 171, 79, 169, 183, 76])
    end

    it 'parses the public key' do
      expect(@private_key.public_key).to eq([108, 35, 192, 26, 47, 128, 233, 165, 133, 38, 242, 5, 76, 55, 135, 40,
                                             103, 72, 230, 43, 184, 117, 219, 37, 173, 250, 196, 122, 252, 174, 173, 140]) # rubocop:disable Layout/LineLength
    end

    it 'parses the secret key' do
      expect(@private_key.secret_key).to eq([65, 87, 110, 33, 168, 130, 118, 100, 249, 200, 160, 167, 47, 59, 141,
                                             122, 156, 38, 80, 199, 139, 1, 21, 18, 116, 110, 204, 131, 199, 202, 181, 87]) # rubocop:disable Layout/LineLength
    end

    it 'parses the checksum' do
      expect(@private_key.checksum).to eq([19, 146, 239, 121, 33, 164, 216, 219, 8, 104, 111, 52, 198, 78, 21, 236,
                                           113, 255, 174, 47, 39, 216, 61, 198, 233, 161, 233, 143, 84, 246, 255, 150])
    end
  end

  describe 'sign' do
    it 'signs a file' do
      @filename = 'encrypted-key.txt'
      @message = SecureRandom.uuid
      File.write("test/generated/#{@filename}", @message)
      signature = @private_key.sign(@filename, @message, 'this is a trusted comment')
      File.write("test/generated/#{@filename}.minisig", signature)
      @signature = Minisign::Signature.new(signature)
      @public_key = Minisign::PublicKey.new('RWSmKaOrT6m3TGwjwBovgOmlhSbyBUw3hyhnSOYruHXbJa36xHr8rq2M')
      expect(@public_key.verify(@signature, @message)).to match('Signature and comment signature verified')
    end
    it 'signs a file with an unencrypted key' do
      @filename = 'unencrypted-key.txt'
      @message = SecureRandom.uuid
      File.write("test/generated/#{@filename}", @message)
      @unencrypted_private_key = Minisign::PrivateKey.new(File.read('test/unencrypted.key'))
      signature = @unencrypted_private_key.sign(@filename, @message)
      File.write("test/generated/#{@filename}.minisig", signature)
      @signature = Minisign::Signature.new(signature)
      @public_key = Minisign::PublicKey.new('RWT/N/MXaBIWRAPzfdEKqVRq9txskjf5qh7EbqMLVHjkNTGFazO3zMw2')
      expect(@public_key.verify(@signature, @message)).to match('Signature and comment signature verified')
    end
  end
end
