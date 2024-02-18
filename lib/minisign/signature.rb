# frozen_string_literal: true

module Minisign
  # Parse a .minisig file's contents
  class Signature
    include Utils
    # @param str [String] The contents of the .minisig file
    # @example
    #   Minisign::Signature.new(File.read('test/example.txt.minisig'))
    def initialize(str)
      @lines = str.split("\n")
      @decoded = Base64.strict_decode64(@lines[1])
    end

    # @return [String] the key id
    # @example
    #   Minisign::Signature.new(File.read('test/example.txt.minisig')).key_id
    #   #=> "E86FECED695E8E0"
    def key_id
      hex @decoded[2..9].bytes
    end

    # @return [String] the trusted comment
    # @example
    #   Minisign::Signature.new(File.read('test/example.txt.minisig')).trusted_comment
    #   #=> "timestamp:1653934067\tfile:example.txt\thashed"
    def trusted_comment
      @lines[2].split('trusted comment: ')[1]
    end

    # @return [String] the signature for the trusted comment
    def trusted_comment_signature
      Base64.decode64(@lines[3])
    end

    # @return [String] the global signature
    def signature
      @decoded[10..]
    end

    # @return [String] The signature that can be written to a file
    def to_s
      "#{@lines.join("\n")}\n"
    end
  end
end
