# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name        = 'minisign'
  s.version     = '0.0.5'
  s.summary     = 'Minisign, in Ruby!'
  s.description = 'Verify minisign signatures'
  s.authors     = ['Jesse Shawl']
  s.email       = 'jesse@jesse.sh'
  s.files       = ['lib/minisign.rb']
  s.homepage    =
    'https://rubygems.org/gems/minisign'
  s.license = 'MIT'
  s.add_runtime_dependency 'ed25519', '~> 1.3'
  s.required_ruby_version = '>= 2.6.0'
end
