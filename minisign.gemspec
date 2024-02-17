# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name        = 'minisign'
  s.version     = '0.2.0'
  s.summary     = 'Minisign, in Ruby!'
  s.description = 'Verify minisign signatures'
  s.authors     = ['Jesse Shawl']
  s.email       = 'jesse@jesse.sh'
  s.files       = Dir['lib/**/*']
  s.executables << 'minisign'
  s.homepage =
    'https://github.com/jshawl/minisign'
  s.license = 'MIT'
  s.add_runtime_dependency 'ed25519', '~> 1.3'
  s.add_runtime_dependency 'rbnacl', '~> 7.1'
  s.required_ruby_version = '>= 2.7'
  s.metadata['rubygems_mfa_required'] = 'true'
end
