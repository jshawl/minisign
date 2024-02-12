# frozen_string_literal: true

describe 'e2e' do
  it 'shows help/usage' do
    # not implementing legacy formats, for now
    jedisct1 = `test/generated/minisign`.gsub(/^-H.*\n/, '').gsub(/^-l.*\n/, '')
    expect(`minisign`).to eq(jedisct1)
  end
  it 'generates a key pair' do
    path = 'test/generated/cli'
    keyname = 'jedisct1-encrypted'
    exe = 'test/generated/minisign'
    password = SecureRandom.uuid
    command = "echo '#{password}\n#{password}' | #{exe} -G -p #{path}/#{keyname}.pub -s #{path}/#{keyname}.key"
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
end
