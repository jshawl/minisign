# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2024-02-19

### Added
- gemspec metadata

### Fixed
- `Minisign::PublicKey#verify` documentation

## [0.2.0] - 2024-02-17

### Added
- Support for changing or removing the password from the private key
- `minisign` executable
- `Minisign::PrivateKey#sign` adds a new optional `untrusted_comment` argument
- Custom error classes:
  - `Minisign::SignatureVerificationError`
  - `Minisign::PasswordMissingError`
  - `Minisign::PasswordIncorrectError`

### Changed
- `Minisign::PublicKey#verify` now raises `Minisign::SignatureVerificationError` instead of `Ed25519::VerifyError` and specifies whether the global signature or the comment signature failed to verify
- `Minisign::PrivateKey` now raises `Minisign::PasswordMissingError` or `Minisign::PasswordIncorrectError` instead of `RuntimeError`

## [0.1.0] - 2024-02-09

### Added
- Support signing with unencrypted keys
- Generate a new keypair
- Add `#to_s` support to write keys and signatures to file

## [0.0.8] - 2024-02-03

### Added
- Create signatures
- Parse private key
- Use ruby 2.7
  
## [0.0.7] - 2022-06-22

### Changed
- Update bundler version
  
## [0.0.6] - 2022-06-22

### Added
- Verify key id match

## [0.0.5] - 2022-05-30

### Added
- Documentation for YARD (https://www.rubydoc.info/gems/minisign/)

## [0.0.4] - 2022-05-30

### Added
- This CHANGELOG file to hopefully serve as an evolving example of a
  standardized open source project CHANGELOG.

[Unreleased]: https://github.com/jshawl/minisign/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/jshawl/minisign/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/jshawl/minisign/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jshawl/minisign/compare/v0.0.8...v0.1.0
[0.0.8]: https://github.com/jshawl/minisign/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/jshawl/minisign/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/jshawl/minisign/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/jshawl/minisign/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/jshawl/minisign/releases/tag/v0.0.4
