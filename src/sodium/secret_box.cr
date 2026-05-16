# src/sodium/secret_box.cr
require "./lib_sodium"
require "./secure_buffer"
require "./error"
require "./nonce"

module Sodium
  class SecretBox
    KEY_SIZE   = LibSodium.crypto_secretbox_keybytes.to_i32
    NONCE_SIZE = LibSodium.crypto_secretbox_noncebytes.to_i32
    MAC_SIZE   = LibSodium.crypto_secretbox_macbytes.to_i32

    @key : SecureBuffer

    def initialize(@key : SecureBuffer)
    end

    # --- Constructors ---
    def self.copy_from(key : Bytes)
      new(SecureBuffer.copy_from(key))
    end

    def self.random
      key = SecureBuffer.new(KEY_SIZE)
      key.readwrite do |buf|
        LibSodium.randombytes_buf(buf, KEY_SIZE)
      end
      new(key)
    end

    # --- Combined mode ---
    # Returns ciphertext and nonce as Bytes
    def encrypt(message : String | Bytes) : {Bytes, Bytes}
      nonce = Nonce.random.to_slice
      ct = encrypt(message, nonce: nonce)
      {ct, nonce}
    end

    def encrypt(message : String | Bytes, *, nonce : Bytes) : Bytes
      msg = message.is_a?(String) ? message.to_slice : message
      raise ArgumentError.new("nonce must be #{NONCE_SIZE} bytes") unless nonce.bytesize == NONCE_SIZE
      dst = Bytes.new(msg.bytesize + MAC_SIZE)
      @key.readonly do |k|
        if LibSodium.crypto_secretbox_easy(dst, msg, msg.bytesize, nonce, k) != 0
          raise Sodium::Error.new("Encryption failed")
        end
      end
      dst
    end

    def decrypt_string(ciphertext : Bytes, *, nonce : Bytes) : String
      String.new(decrypt(ciphertext, nonce: nonce))
    end

    def decrypt(ciphertext : Bytes, *, nonce : Bytes) : Bytes
      raise ArgumentError.new("ciphertext too short") if ciphertext.bytesize < MAC_SIZE
      raise ArgumentError.new("nonce must be #{NONCE_SIZE} bytes") unless nonce.bytesize == NONCE_SIZE
      dst = Bytes.new(ciphertext.bytesize - MAC_SIZE)
      @key.readonly do |k|
        if LibSodium.crypto_secretbox_open_easy(dst, ciphertext, ciphertext.bytesize, nonce, k) != 0
          raise Sodium::Error::DecryptionFailed.new
        end
      end
      dst
    end

    # --- Detached mode ---
    def encrypt_detached(message : String | Bytes, nonce : Bytes) : {Bytes, Bytes}
      msg = message.is_a?(String) ? message.to_slice : message
      raise ArgumentError.new("nonce must be #{NONCE_SIZE} bytes") unless nonce.bytesize == NONCE_SIZE
      ct = Bytes.new(msg.bytesize)
      mac = Bytes.new(MAC_SIZE)
      @key.readonly do |k|
        if LibSodium.crypto_secretbox_detached(ct, mac, msg, msg.bytesize, nonce, k) != 0
          raise Sodium::Error.new("Encryption failed")
        end
      end
      {ct, mac}
    end

    def decrypt_detached(ciphertext : Bytes, mac : Bytes, nonce : Bytes) : Bytes
      raise ArgumentError.new("mac must be #{MAC_SIZE} bytes") unless mac.bytesize == MAC_SIZE
      raise ArgumentError.new("nonce must be #{NONCE_SIZE} bytes") unless nonce.bytesize == NONCE_SIZE
      dst = Bytes.new(ciphertext.bytesize)
      @key.readonly do |k|
        if LibSodium.crypto_secretbox_open_detached(dst, ciphertext, mac, ciphertext.bytesize, nonce, k) != 0
          raise Sodium::Error::DecryptionFailed.new
        end
      end
      dst
    end

    def decrypt_detached_string(ciphertext : Bytes, mac : Bytes, nonce : Bytes) : String
      String.new(decrypt_detached(ciphertext, mac, nonce))
    end

    # --- Key access ---
    def key : SecureBuffer
      @key
    end
  end
end
