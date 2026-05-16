# src/sodium/cipher/aegis.cr
require "../lib_sodium"
require "../secure_buffer"
require "../error"

module Sodium
  module Cipher
    class Aegis128L
      KEY_BYTES  = LibSodium.crypto_aead_aegis128l_keybytes.to_i32
      NPUB_BYTES = LibSodium.crypto_aead_aegis128l_npubbytes.to_i32
      ABYTES     = LibSodium.crypto_aead_aegis128l_abytes.to_i32

      def self.encrypt(message : String | Bytes, nonce : Bytes, key : Bytes | SecureBuffer, additional_data : Bytes? = nil) : Bytes
        key_ptr = key.is_a?(SecureBuffer) ? key.to_unsafe : key
        msg = message.is_a?(String) ? message.to_slice : message
        ad_ptr = additional_data ? additional_data.to_unsafe : Pointer(UInt8).null
        ad_len = additional_data ? additional_data.bytesize.to_u64 : 0_u64

        dst = Bytes.new(msg.bytesize + ABYTES)
        len_out = uninitialized UInt64
        if LibSodium.crypto_aead_aegis128l_encrypt(dst, pointerof(len_out), msg, msg.bytesize, ad_ptr, ad_len, nil, nonce, key_ptr) != 0
          raise Sodium::Error.new("AEGIS‑128L encryption failed")
        end
        dst
      end

      def self.decrypt(ciphertext : Bytes, nonce : Bytes, key : Bytes | SecureBuffer, additional_data : Bytes? = nil) : Bytes
        key_ptr = key.is_a?(SecureBuffer) ? key.to_unsafe : key
        ad_ptr = additional_data ? additional_data.to_unsafe : Pointer(UInt8).null
        ad_len = additional_data ? additional_data.bytesize.to_u64 : 0_u64

        if ciphertext.bytesize < ABYTES
          raise Sodium::Error.new("Ciphertext too short")
        end
        dst = Bytes.new(ciphertext.bytesize - ABYTES)
        len_out = uninitialized UInt64
        if LibSodium.crypto_aead_aegis128l_decrypt(dst, pointerof(len_out), nil, ciphertext, ciphertext.bytesize, ad_ptr, ad_len, nonce, key_ptr) != 0
          raise Sodium::Error.new("AEGIS‑128L decryption failed")
        end
        dst
      end
    end

    class Aegis256
      KEY_BYTES  = LibSodium.crypto_aead_aegis256_keybytes.to_i32
      NPUB_BYTES = LibSodium.crypto_aead_aegis256_npubbytes.to_i32
      ABYTES     = LibSodium.crypto_aead_aegis256_abytes.to_i32

      def self.encrypt(message : String | Bytes, nonce : Bytes, key : Bytes | SecureBuffer, additional_data : Bytes? = nil) : Bytes
        key_ptr = key.is_a?(SecureBuffer) ? key.to_unsafe : key
        msg = message.is_a?(String) ? message.to_slice : message
        ad_ptr = additional_data ? additional_data.to_unsafe : Pointer(UInt8).null
        ad_len = additional_data ? additional_data.bytesize.to_u64 : 0_u64

        dst = Bytes.new(msg.bytesize + ABYTES)
        len_out = uninitialized UInt64
        if LibSodium.crypto_aead_aegis256_encrypt(dst, pointerof(len_out), msg, msg.bytesize, ad_ptr, ad_len, nil, nonce, key_ptr) != 0
          raise Sodium::Error.new("AEGIS‑256 encryption failed")
        end
        dst
      end

      def self.decrypt(ciphertext : Bytes, nonce : Bytes, key : Bytes | SecureBuffer, additional_data : Bytes? = nil) : Bytes
        key_ptr = key.is_a?(SecureBuffer) ? key.to_unsafe : key
        ad_ptr = additional_data ? additional_data.to_unsafe : Pointer(UInt8).null
        ad_len = additional_data ? additional_data.bytesize.to_u64 : 0_u64

        if ciphertext.bytesize < ABYTES
          raise Sodium::Error.new("Ciphertext too short")
        end
        dst = Bytes.new(ciphertext.bytesize - ABYTES)
        len_out = uninitialized UInt64
        if LibSodium.crypto_aead_aegis256_decrypt(dst, pointerof(len_out), nil, ciphertext, ciphertext.bytesize, ad_ptr, ad_len, nonce, key_ptr) != 0
          raise Sodium::Error.new("AEGIS‑256 decryption failed")
        end
        dst
      end
    end
  end
end
