module Minisign
    module NaCl
        def self.safely
            begin
                yield
            rescue NameError
                raise Minisign::LibSodiumDependencyError, 'libsodium is not installed!'
            end
        end
        module Hash
            module Blake2b
                def self.digest(*args)
                    NaCl::safely do
                        RbNaCl::Hash::Blake2b.digest(*args)
                    end
                end
            end
        end
        module PasswordHash
            def self.scrypt(*args)
                NaCl::safely do
                    RbNaCl::PasswordHash.scrypt(*args)
                end
            end
        end
    end
end