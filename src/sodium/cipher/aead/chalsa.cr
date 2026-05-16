# src/sodium/cipher/aead/chalsa.cr
require "../../lib_sodium"
require "../../secure_buffer"
require "../../nonce"

module Sodium::Cipher::Aead
  abstract struct Chalsa
    getter key : SecureBuffer

    @[Deprecated("use .random instead of .new")]
    def initialize
      @key = SecureBuffer.random key_size
    end

    def initialize(@key : SecureBuffer)
      raise ArgumentError.new("key size mismatch, got #{@key.bytesize}, wanted #{key_size}") if @key.bytesize != key_size
      @key.readonly
    end

    def initialize(bytes : Bytes, erase = false)
      raise ArgumentError.new("key size mismatch, got #{bytes.bytesize}, wanted #{key_size}") if bytes.bytesize != key_size
      @key = erase ? SecureBuffer.move_from(bytes) : SecureBuffer.copy_from(bytes)
    end

    def encrypt(src, dst : Bytes? = nil, *, nonce = nil, additional = nil) : {Bytes, Nonce}
      offset = src.bytesize
      dst ||= Bytes.new(offset + mac_size)
      mac = dst[offset, mac_size]
      _, _, nonce = encrypt_detached src.to_slice, dst[0, offset], mac: mac, nonce: nonce, additional: additional
      {dst, nonce}
    end

    def decrypt_secret(src, dst : Crypto::Secret? = nil, *, nonce : Nonce, additional = nil) : Crypto::Secret
      dst ||= Sodium::SecureBuffer.new(src.bytesize - mac_size)
      dst.readwrite do |dslice|
        decrypt src, dslice, nonce: nonce, additional: additional
      end
      dst.readonly
    end

    def decrypt(src, dst : Bytes? = nil, *, nonce : Nonce, additional = nil) : Bytes
      src = src.to_slice
      offset = src.bytesize - mac_size
      mac = src[offset, mac_size]
      decrypt_detached src[0, offset], dst, nonce: nonce, mac: mac, additional: additional
    end

    def decrypt_string(src, *, nonce : Nonce, additional = nil) : String
      dsize = src.bytesize - mac_size
      String.new(dsize) do |dst|
        decrypt src, dst.to_slice(dsize), nonce: nonce, additional: additional
        {dsize, dsize}
      end
    end

    def encrypt_detached(src, dst : Bytes? = nil, *, nonce = nil, mac : Bytes? = nil, additional = nil) : {Bytes, Bytes, Nonce}
      encrypt_detached src.to_slice, mac: mac, nonce: nonce, additional: additional
    end

    def decrypt_detached(src, dst : Bytes? = nil, *, nonce = nil, mac : Bytes? = nil, additional = nil) : Bytes
      decrypt_detached src.to_slice, mac: mac, nonce: nonce, additional: additional
    end

    def decrypt_detached_string(src, *, nonce = nil, mac : Bytes? = nil, additional = nil) : String
      dsize = src.bytesize
      String.new(dsize) do |dst|
        decrypt_detached src.to_slice, dst.to_slice(dsize), mac: mac, nonce: nonce, additional: additional
        {dsize, dsize}
      end
    end

    abstract def encrypt_detached(src : Bytes, dst : Bytes? = nil, *, nonce : Sodium::Nonce? = nil, mac : Bytes? = nil, additional : String | Bytes | Nil = nil) : {Bytes, Bytes, Sodium::Nonce}
    abstract def decrypt_detached(src : Bytes, dst : Bytes? = nil, *, nonce : Sodium::Nonce, mac : Bytes, additional : String | Bytes | Nil = nil) : Bytes
    abstract def key_size : Int32
    abstract def mac_size : Int32
    abstract def nonce_size : Int32

    def dup
      self.class.new @key.dup
    end
  end

  {% for key, val in {"ChaCha20Poly1305" => "_chacha20poly1305", "ChaCha20Poly1305Ietf" => "_chacha20poly1305_ietf", "XChaCha20Poly1305Ietf" => "_xchacha20poly1305_ietf"} %}
    struct {{ key.id }} < Chalsa
      KEY_SIZE = LibSodium.crypto_aead{{ val.id }}_keybytes.to_i32
      MAC_SIZE = LibSodium.crypto_aead{{ val.id }}_abytes.to_i32
      NONCE_SIZE = LibSodium.crypto_aead{{ val.id }}_npubbytes.to_i32

      def self.random
        key = SecureBuffer.random KEY_SIZE
        new key
      end

      # Static encrypt/decrypt using raw Bytes (bypasses Nonce class).
      def self.encrypt_static(message : String | Bytes, nonce : Bytes, key : Bytes, additional : Bytes? = nil) : Bytes
        raise ArgumentError.new("nonce size mismatch") unless nonce.bytesize == NONCE_SIZE
        raise ArgumentError.new("key size mismatch") unless key.bytesize == KEY_SIZE
        msg = message.is_a?(String) ? message.to_slice : message
        ad_ptr = additional ? additional.to_unsafe : Pointer(UInt8).null
        ad_len = additional ? additional.bytesize.to_u64 : 0_u64

        dst = Bytes.new(msg.bytesize + MAC_SIZE)
        len_out = uninitialized UInt64
        if LibSodium.crypto_aead{{ val.id }}_encrypt_detached(dst, dst + msg.bytesize, pointerof(len_out), msg, msg.bytesize, ad_ptr, ad_len, nil, nonce, key) != 0
          raise Sodium::Error.new("crypto_aead{{ val.id }}_encrypt_detached failed")
        end
        dst
      end

      def self.decrypt_static(ciphertext : Bytes, nonce : Bytes, key : Bytes, additional : Bytes? = nil) : Bytes
        raise ArgumentError.new("nonce size mismatch") unless nonce.bytesize == NONCE_SIZE
        raise ArgumentError.new("key size mismatch") unless key.bytesize == KEY_SIZE
        raise Sodium::Error.new("ciphertext too short") if ciphertext.bytesize < MAC_SIZE

        ad_ptr = additional ? additional.to_unsafe : Pointer(UInt8).null
        ad_len = additional ? additional.bytesize.to_u64 : 0_u64

        dst = Bytes.new(ciphertext.bytesize - MAC_SIZE)
        if LibSodium.crypto_aead{{ val.id }}_decrypt_detached(dst, nil, ciphertext, ciphertext.bytesize - MAC_SIZE,
                                                              ciphertext + (ciphertext.bytesize - MAC_SIZE),
                                                              ad_ptr, ad_len, nonce, key) != 0
          raise Sodium::Error.new("crypto_aead{{ val.id }}_decrypt_detached failed")
        end
        dst
      end

      # Instance methods implementing abstract defs
      def encrypt_detached(src : Bytes, dst : Bytes? = nil, *, nonce : Sodium::Nonce? = nil, mac : Bytes? = nil, additional : String | Bytes | Nil = nil) : {Bytes, Bytes, Sodium::Nonce}
        dst ||= Bytes.new src.bytesize
        nonce ||= Sodium::Nonce.random
        mac ||= Bytes.new MAC_SIZE

        raise ArgumentError.new("src and dst bytesize must be identical #{src.bytesize} != #{dst.bytesize}") if src.bytesize != dst.bytesize
        raise ArgumentError.new("nonce size mismatch, got #{nonce.bytesize}, wanted #{NONCE_SIZE}") unless nonce.bytesize == NONCE_SIZE
        raise ArgumentError.new("mac size mismatch, got #{mac.bytesize}, wanted #{MAC_SIZE}") unless mac.bytesize == MAC_SIZE

        additional = additional.try &.to_slice
        ad_len = additional.try(&.bytesize) || 0

        nonce.used!
        @key.readonly do |kslice|
          r = LibSodium.crypto_aead{{ val.id }}_encrypt_detached(dst, mac, out mac_len, src, src.bytesize, additional, ad_len, nil, nonce.to_slice, kslice)
          raise Sodium::Error.new("crypto_aead_{{ val.id }}_encrypt_detached") if r != 0
          raise Sodium::Error.new("crypto_aead_{{ val.id }}_encrypt_detached mac size mismatch") if mac_len != MAC_SIZE
        end

        {mac, dst, nonce}
      end

      def decrypt_detached(src : Bytes, dst : Bytes? = nil, *, nonce : Sodium::Nonce, mac : Bytes, additional : String | Bytes | Nil = nil) : Bytes
        dst ||= Bytes.new src.bytesize
        raise ArgumentError.new("src and dst bytesize must be identical #{src.bytesize} != #{dst.bytesize}") if src.bytesize != dst.bytesize
        raise ArgumentError.new("nonce size mismatch, got #{nonce.bytesize}, wanted #{NONCE_SIZE}") unless nonce.bytesize == NONCE_SIZE
        raise ArgumentError.new("mac size mismatch, got #{mac.bytesize}, wanted #{MAC_SIZE}") unless mac.bytesize == MAC_SIZE

        ad_len = additional.try(&.bytesize) || 0

        r = @key.readonly do |kslice|
          LibSodium.crypto_aead{{ val.id }}_decrypt_detached(dst, nil, src, src.bytesize, mac, additional, ad_len, nonce.to_slice, kslice)
        end
        raise Sodium::Error::DecryptionFailed.new("crypto_aead_{{ val.id }}_decrypt_detached") if r != 0
        dst
      end

      def key_size : Int32
        KEY_SIZE
      end

      def mac_size : Int32
        MAC_SIZE
      end

      def nonce_size : Int32
        NONCE_SIZE
      end
    end
  {% end %}
end
