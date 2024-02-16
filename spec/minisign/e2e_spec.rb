# frozen_string_literal: true

describe 'e2e' do
  it 'shows help/usage' do
    # not implementing legacy formats, for now
    jedisct1 = `test/generated/minisign`.gsub(/^-H.*\n/, '').gsub(/^-l.*\n/, '')
    expect(`minisign`).to eq(jedisct1)
  end
  it 'generates a key pair' do
    path = 'test/generated/cli'
    keyname = 'ruby-encrypted'
    exe = 'minisign'
    password = SecureRandom.uuid
    # TODO: prompt a second time for password confirmation
    command = "echo '#{password}' | #{exe} -G -p #{path}/#{keyname}.pub -s #{path}/#{keyname}.key"
    `#{command}`
    # prompt -f
    expect(`#{command} 2>&1`).to match('Key generation aborted:')
    output = `#{command} -f`
    expect(output).not_to match('Key generation aborted:')
    expect(output).to match("The secret key was saved as #{path}/#{keyname}.key - Keep it secret!")
    expect(output).to match("The public key was saved as #{path}/#{keyname}.pub - That one can be public.")
    public_key = File.read("#{path}/#{keyname}.pub").split("\n").pop
    expect(output.gsub('+', '')).to match("minisign -Vm <file> -P #{public_key}".gsub('+', ''))
  end
  it 'signs files' do
    path = 'test/generated'
    trusted_comment = SecureRandom.uuid
    command = "echo 'password' | minisign -Sm #{path}/.keep -s test/minisign.key -t #{trusted_comment}"
    `#{command}`
    ruby_signature = File.read("#{path}/.keep.minisig")
    command = "echo 'password' | #{path}/minisign -Sm #{path}/.keep -s test/minisign.key -t #{trusted_comment}"
    `#{command}`
    jedisct1_signature = File.read("#{path}/.keep.minisig")
    expect(ruby_signature).to eq(jedisct1_signature)
  end
  it 'verifies files' do
    path = 'test/generated'
    command = "minisign -Vm #{path}/.keep -p test/minisign.pub"
    expect(`#{command}`).to match(/Signature and comment signature verified\nTrusted comment: [a-z0-9-]+/)
    command = "minisign -Vm #{path}/.keep -p test/minisign.pub -Q"
    expect(`#{command}`).to match(/^[a-z0-9-]+$/)
    command = "minisign -Vm #{path}/.keep -p test/minisign.pub -q"
    expect(`#{command}`).to eq('')
  end
  it 'shows an error message when the signature is invalid' do
    command = 'minisign -Vm test/example.txt -x test/example.txt.minisig.unverifiable -p test/minisign.pub'
    expect(`#{command}`).to match(/Signature verification failed/)
    command = 'minisign -Vm test/example.txt -x test/example.txt.minisig.tampered -p test/minisign.pub'
    expect(`#{command}`).to match(/Signature verification failed/)
  end
end
