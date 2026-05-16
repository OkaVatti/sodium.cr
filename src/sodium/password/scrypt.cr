# src/sodium/password/scrypt.cr
require "../lib_sodium"
require "../secure_buffer"
require "../error"
require "./abstract"

module Sodium::Password
  # Scrypt password hashing (for compatibility with older applications).
  # New applications should use Argon2 via `Password::Key` or `Password::Hash`.
  class Scrypt < Abstract
    SALT_SIZE = LibSodium.crypto_pwhash_scryptsalsa208sha256_saltbytes.to_i
    STR_SIZE  = LibSodium.crypto_pwhash_scryptsalsa208sha256_strbytes.to_i

    # Predefined limits
    OPSLIMIT_MIN         = LibSodium.crypto_pwhash_scryptsalsa208sha256_opslimit_min.to_u64
    OPSLIMIT_MAX         = LibSodium.crypto_pwhash_scryptsalsa208sha256_opslimit_max.to_u64
    MEMLIMIT_MIN         = LibSodium.crypto_pwhash_scryptsalsa208sha256_memlimit_min.to_u64
    MEMLIMIT_MAX         = LibSodium.crypto_pwhash_scryptsalsa208sha256_memlimit_max.to_u64
    OPSLIMIT_INTERACTIVE = LibSodium.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive.to_u64
    MEMLIMIT_INTERACTIVE = LibSodium.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive.to_u64
    OPSLIMIT_SENSITIVE   = LibSodium.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive.to_u64
    MEMLIMIT_SENSITIVE   = LibSodium.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive.to_u64

    # Derive a key of `key_len` bytes from `pass` and `salt`.
    def derive_key(pass : String | Bytes, key_len : Int32, salt : Bytes) : SecureBuffer
      pwd = pass.is_a?(String) ? pass.to_slice : pass
      raise ArgumentError.new("key_len out of range") unless key_len >= LibSodium.crypto_pwhash_scryptsalsa208sha256_bytes_min && key_len <= LibSodium.crypto_pwhash_scryptsalsa208sha256_bytes_max
      raise ArgumentError.new("salt must be #{SALT_SIZE} bytes") unless salt.bytesize == SALT_SIZE

      key = SecureBuffer.new(key_len)
      key.readwrite do |k|
        if LibSodium.crypto_pwhash_scryptsalsa208sha256(k, key_len, pwd, pwd.bytesize, salt, @ops, @mem) != 0
          raise Sodium::Error.new("scrypt key derivation failed")
        end
      end
      key.readonly
    end

    # Create a storable hash string.
    def create_str(pass : String | Bytes) : String
      pwd = pass.is_a?(String) ? pass.to_slice : pass
      buf = Bytes.new(STR_SIZE)
      if LibSodium.crypto_pwhash_scryptsalsa208sha256_str(buf, pwd, pwd.bytesize, @ops, @mem) != 0
        raise Sodium::Error.new("scrypt hash creation failed")
      end
      String.new(buf.to_unsafe)
    end

    # Verify a password against a previously created hash string.
    def verify_str(hash : String, pass : String | Bytes) : Bool
      pwd = pass.is_a?(String) ? pass.to_slice : pass
      LibSodium.crypto_pwhash_scryptsalsa208sha256_str_verify(hash, pwd, pwd.bytesize) == 0
    end

    # Check if a hash string needs rehashing with current ops/mem limits.
    def needs_rehash?(hash : String) : Bool
      LibSodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(hash, @ops, @mem) != 0
    end
  end
end
