# src/sodium/cipher/aes256_gcm.cr
require "../lib_sodium"
require "../secure_buffer"
require "../error"

module Sodium
  module Cipher
    # AES256‑GCM AEAD (hardware‑accelerated on most x86 CPUs, falls back to software).
    class Aes256Gcm
      KEY_BYTES  = LibSodium.crypto_aead_aes256gcm_keybytes.to_i32
      NPUB_BYTES = LibSodium.crypto_aead_aes256gcm_npubbytes.to_i32
      ABYTES     = LibSodium.crypto_aead_aes256gcm_abytes.to_i32

      # Returns true if the CPU supports AESNI (hardware AES).
      def self.available? : Bool
        LibSodium.crypto_aead_aes256gcm_is_available != 0
      end

      # Encrypts `message` with `nonce`, `key`, and optional `additional_data`.
      # Returns the combined ciphertext (ciphertext || tag).
      def self.encrypt(message : String | Bytes, nonce : Bytes, key : Bytes | SecureBuffer, additional_data : Bytes? = nil) : Bytes
        raise Sodium::Error.new("AES256-GCM is not available on this CPU") unless available?
        key_ptr = key.is_a?(SecureBuffer) ? key.to_unsafe : key
        msg = message.is_a?(String) ? message.to_slice : message
        ad_ptr = additional_data ? additional_data.to_unsafe : Pointer(UInt8).null
        ad_len = additional_data ? additional_data.bytesize.to_u64 : 0_u64

        dst = Bytes.new(msg.bytesize + ABYTES)
        len_out = uninitialized UInt64
        if LibSodium.crypto_aead_aes256gcm_encrypt(dst, pointerof(len_out), msg, msg.bytesize,
             ad_ptr, ad_len, nil, nonce, key_ptr) != 0
          raise Sodium::Error.new("AES256-GCM encryption failed")
        end
        dst
      end

      # Decrypts `ciphertext` (combined ciphertext || tag) and returns the plaintext.
      def self.decrypt(ciphertext : Bytes, nonce : Bytes, key : Bytes | SecureBuffer, additional_data : Bytes? = nil) : Bytes
        raise Sodium::Error.new("AES256-GCM is not available on this CPU") unless available?
        key_ptr = key.is_a?(SecureBuffer) ? key.to_unsafe : key
        ad_ptr = additional_data ? additional_data.to_unsafe : Pointer(UInt8).null
        ad_len = additional_data ? additional_data.bytesize.to_u64 : 0_u64

        if ciphertext.bytesize < ABYTES
          raise Sodium::Error.new("Ciphertext too short")
        end
        dst = Bytes.new(ciphertext.bytesize - ABYTES)
        len_out = uninitialized UInt64
        if LibSodium.crypto_aead_aes256gcm_decrypt(dst, pointerof(len_out), nil,
             ciphertext, ciphertext.bytesize,
             ad_ptr, ad_len, nonce, key_ptr) != 0
          raise Sodium::Error.new("AES256-GCM decryption failed")
        end
        dst
      end
    end
  end
end
