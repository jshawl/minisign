# frozen_string_literal: true

require 'io/console'

# rubocop:disable Metrics/ModuleLength
module Minisign
  # The command line interface
  module CLI
    # rubocop:disable Metrics/AbcSize
    # rubocop:disable Metrics/MethodLength
    def self.usage
      puts 'Usage:'
      puts 'minisign -G [-f] [-p pubkey_file] [-s seckey_file] [-W]'
      puts 'minisign -R [-s seckey_file] [-p pubkey_file]'
      puts 'minisign -C [-s seckey_file] [-W]'
      puts 'minisign -S [-l] [-x sig_file] [-s seckey_file] [-c untrusted_comment]'
      puts '            [-t trusted_comment] -m file [file ...]'
      puts 'minisign -V [-H] [-x sig_file] [-p pubkey_file | -P pubkey] [-o] [-q] -m file'
      puts ''
      puts '-G                generate a new key pair'
      puts '-R                recreate a public key file from a secret key file'
      puts '-C                change/remove the password of the secret key'
      puts '-S                sign files'
      puts '-V                verify that a signature is valid for a given file'
      puts '-m <file>         file to sign/verify'
      puts '-o                combined with -V, output the file content after verification'
      puts '-p <pubkey_file>  public key file (default: ./minisign.pub)'
      puts '-P <pubkey>       public key, as a base64 string'
      puts '-s <seckey_file>  secret key file (default: ~/.minisign/minisign.key)'
      puts '-W                do not encrypt/decrypt the secret key with a password'
      puts '-x <sigfile>      signature file (default: <file>.minisig)'
      puts '-c <comment>      add a one-line untrusted comment'
      puts '-t <comment>      add a one-line trusted comment'
      puts '-q                quiet mode, suppress output'
      puts '-Q                pretty quiet mode, only print the trusted comment'
      puts '-f                force. Combined with -G, overwrite a previous key pair'
      puts '-v                display version number'
      puts ''
    end
    # rubocop:enable Metrics/MethodLength

    def self.prompt
      $stdin.tty? ? $stdin.noecho(&:gets).chomp : $stdin.gets.chomp
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
        print " done\n"
        puts "The secret key was saved as #{options[:s]} - Keep it secret!"
        File.write(public_key, keypair.public_key)
        puts "The public key was saved as #{options[:p]} - That one can be public."
        pubkey = keypair.public_key.to_s.split("\n").pop
        puts "minisign -Vm <file> -P #{pubkey}"
      end
    end
    # rubocop:enable Metrics/MethodLength

    def self.recreate(options)
      secret_key = options[:s] || "#{Dir.home}/.minisign/minisign.key"
      public_key = options[:p] || './minisign.pub'
      private_key_contents = File.read(secret_key)
      begin
        # try without a password first
        private_key = Minisign::PrivateKey.new(private_key_contents)
      rescue Minisign::PasswordMissingError
        print 'Password: '
        private_key = Minisign::PrivateKey.new(private_key_contents, prompt)
      end
      File.write(public_key, private_key.public_key)
    end

    def self.change_password(options)
      options[:s] ||= "#{Dir.home}/.minisign/minisign.key"
      print 'Password: '
      private_key = Minisign::PrivateKey.new(File.read(options[:s]), prompt)
      print 'New Password: '
      new_password = options[:W] ? nil : prompt
      private_key.change_password! new_password
      File.write(options[:s], private_key)
    end

    def self.sign(options)
      # TODO: multiple files
      options[:x] ||= "#{options[:m]}.minisig"
      options[:s] ||= "#{Dir.home}/.minisign/minisign.key"
      private_key = begin
        Minisign::PrivateKey.new(File.read(options[:s]))
      rescue Minisign::PasswordMissingError
        print 'Password: '
        Minisign::PrivateKey.new(File.read(options[:s]), prompt)
      end
      signature = private_key.sign(options[:m], File.read(options[:m]), options[:t])
      File.write(options[:x], signature)
    end

    def self.verify(options)
      options[:x] ||= "#{options[:m]}.minisig"
      options[:p] ||= './minisign.pub'
      options[:P] ||= File.read(options[:p])
      public_key = Minisign::PublicKey.new(options[:P])
      message = File.read(options[:m])
      signature = Minisign::Signature.new(File.read(options[:x]))
      verification = public_key.verify(signature, message)
      return if options[:q]
      return puts message if options[:o]

      puts options[:Q] ? signature.trusted_comment : verification
    end
    # rubocop:enable Metrics/AbcSize
  end
end

# rubocop:enable Metrics/ModuleLength
