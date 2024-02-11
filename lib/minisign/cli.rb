# frozen_string_literal: true

require 'io/console'

module Minisign
  # The command line interface
  module CLI
    # lol
    def self.help
      puts '-G                  generate a new key pair'
      puts '-R                  recreate a public key file from a secret key file'
      puts '-f                  force. Combined with -G, overwrite a previous key pair'
      puts '-p <pubkey_file>    public key file (default: ./minisign.pub)'
      puts '-s <seckey_file>    secret key file (default: ~/.minisign/minisign.key)'
      puts '-W                  do not encrypt/decrypt the secret key with a password'
    end

    def self.usage
      puts 'Usage:'
      puts 'minisign -G [-f] [-p pubkey_file] [-s seckey_file] [-W]'
      puts 'minisign -R [-s seckey_file] [-p pubkey_file]'
    end

    def self.prompt
      $stdin.noecho(&:gets).chomp
    end

    def self.prevent_overwrite!(file)
      return unless File.exist? file

      puts 'Key generation aborted:'
      puts "#{file} already exists."
      puts ''
      puts 'If you really want to overwrite the existing key pair, add the -f switch to'
      puts 'force this operation.'
      exit 1
    end

    # rubocop:disable Metrics/AbcSize
    # rubocop:disable Metrics/MethodLength
    def self.generate(options)
      secret_key = options[:s] || "#{Dir.home}/.minisign/minisign.key"
      public_key = options[:p] || './minisign.pub'
      prevent_overwrite!(public_key) unless options[:f]
      prevent_overwrite!(secret_key) unless options[:f]

      if options[:W]
        keypair = Minisign::KeyPair.new
        File.write(secret_key, keypair.private_key)
        File.write(public_key, keypair.public_key)
      else
        print 'Password: '
        password = prompt
        print "\nDeriving a key from the password in order to encrypt the secret key..."
        keypair = Minisign::KeyPair.new(password)
        File.write(secret_key, keypair.private_key)
        File.write(public_key, keypair.public_key)
        print " done\n"
      end
    end
    # rubocop:enable Metrics/MethodLength
    # rubocop:enable Metrics/AbcSize

    def self.recreate(options)
      secret_key = options[:s] || "#{Dir.home}/.minisign/minisign.key"
      public_key = options[:p] || './minisign.pub'
      private_key_contents = File.read(secret_key)
      begin
        # try without a password first
        private_key = Minisign::PrivateKey.new(private_key_contents)
      rescue RuntimeError
        print 'Password: '
        private_key = Minisign::PrivateKey.new(private_key_contents, prompt)
      end
      File.write(public_key, private_key.public_key)
    end

    def self.change_password(options)
      options[:s] || "#{Dir.home}/.minisign/minisign.key"
      print 'Password: '
      private_key = Minisign::PrivateKey.new(File.read(options[:s]), prompt)
      print 'New Password: '
      new_password = prompt
      private_key.change_password! new_password
      File.write(options[:s], private_key)
    end
  end
end
