# frozen_string_literal: true

module Minisign
  # Parse a .minisig file's contents
  class Signature
    # @param str [String] The contents of the .minisig file
    # @example
    #   Minisign::Signature.new(File.read('test/example.txt.minisig'))
    def initialize(str)
      @lines = str.split("\n")
    end

    # @return [String] the key id
    # @example
    #   Minisign::Signature.new(File.read('test/example.txt.minisig')).key_id
    #   #=> "E86FECED695E8E0"
    def key_id
      encoded_signature[2..9].bytes.map { |c| c.to_s(16) }.reverse.join.upcase
    end

    # @return [String] the trusted comment
    # @example
    #   Minisign::Signature.new(File.read('test/example.txt.minisig')).trusted_comment
    #   #=> "timestamp:1653934067\tfile:example.txt\thashed"
    def trusted_comment
      @lines[2].split('trusted comment: ')[1]
    end

    def trusted_comment_signature
      Base64.decode64(@lines[3])
    end

    # @return [String] the signature
    def signature
      encoded_signature[10..]
    end

    private

    def encoded_signature
      Base64.decode64(@lines[1])
    end
  end
end
