# src/sodium/secret_stream.cr
require "./lib_sodium"
require "./secure_buffer"
require "./error"

module Sodium
  # Implements libsodium's crypto_secretstream API for encrypted streams.
  #
  # Usage:
  #   # Encryption
  #   key = SecretStream.keygen
  #   stream = SecretStream::EncryptStream.new(key)
  #   header = stream.header  # Send/store this first
  #   ciphertext1 = stream.push("Hello")
  #   ciphertext2 = stream.push("World", tag: SecretStream::Tag::Final)
  #
  #   # Decryption
  #   stream = SecretStream::DecryptStream.new(header, key)
  #   message1, tag1 = stream.pull(ciphertext1)
  #   message2, tag2 = stream.pull(ciphertext2)
  #   # tag2 should be Tag::Final
  module SecretStream
    # Constants
    KEY_BYTES    = LibSodium.crypto_secretstream_xchacha20poly1305_keybytes.to_i
    HEADER_BYTES = LibSodium.crypto_secretstream_xchacha20poly1305_headerbytes.to_i
    STATE_BYTES  = LibSodium.crypto_secretstream_xchacha20poly1305_statebytes.to_i
    ABYTES       = LibSodium.crypto_secretstream_xchacha20poly1305_abytes.to_i

    # Tag values for messages (as defined in libsodium’s crypto_secretstream.h)
    enum Tag : UInt8
      Message = 0x00_u8
      Push    = 0x01_u8
      Rekey   = 0x02_u8
      Final   = 0x03_u8

      def self.from_c(value : UInt8) : Tag
        case value
        when Tag::Message.value then Tag::Message
        when Tag::Push.value    then Tag::Push
        when Tag::Rekey.value   then Tag::Rekey
        when Tag::Final.value   then Tag::Final
        else
          raise Sodium::Error.new("Unknown tag value: #{value}")
        end
      end
    end

    # Generate a random key for secret stream encryption
    def self.keygen : SecureBuffer
      buf = SecureBuffer.new(KEY_BYTES)
      buf.readwrite do |slice|
        LibSodium.randombytes_buf(slice, KEY_BYTES)
      end
      buf
    end

    # Encryption stream
    class EncryptStream
      getter header : Bytes

      def initialize(key : Bytes | SecureBuffer)
        @state = SecureBuffer.new(STATE_BYTES)
        @header = Bytes.new(HEADER_BYTES)

        key_ptr = key.is_a?(SecureBuffer) ? key.to_unsafe : key

        @state.readwrite do |state_slice|
          if LibSodium.crypto_secretstream_xchacha20poly1305_init_push(
               state_slice, @header, key_ptr
             ) != 0
            raise Sodium::Error.new("Failed to initialize encryption stream")
          end
        end
      end

      # Push a message into the encrypted stream
      def push(message : String | Bytes, tag : Tag = Tag::Message, ad : Bytes? = nil) : Bytes
        ciphertext = Bytes.new(message.bytesize + ABYTES)
        ad_ptr = ad ? ad.to_unsafe : Pointer(UInt8).null
        ad_len = ad ? ad.bytesize : 0_u64

        @state.readwrite do |state_slice|
          out_len = uninitialized UInt64
          if LibSodium.crypto_secretstream_xchacha20poly1305_push(
               state_slice, ciphertext, pointerof(out_len),
               message, message.bytesize.to_u64,
               ad_ptr, ad_len, tag.value.to_u8
             ) != 0
            raise Sodium::Error.new("Encryption failed")
          end
        end

        ciphertext
      end

      # Rekey the stream (for forward secrecy)
      def rekey : Nil
        @state.readwrite do |state_slice|
          LibSodium.crypto_secretstream_xchacha20poly1305_rekey(state_slice)
        end
      end
    end

    # Decryption stream
    class DecryptStream
      def initialize(@header : Bytes, key : Bytes | SecureBuffer)
        raise ArgumentError.new("Invalid header size") unless @header.bytesize == HEADER_BYTES

        @state = SecureBuffer.new(STATE_BYTES)
        key_ptr = key.is_a?(SecureBuffer) ? key.to_unsafe : key

        @state.readwrite do |state_slice|
          if LibSodium.crypto_secretstream_xchacha20poly1305_init_pull(
               state_slice, @header, key_ptr
             ) != 0
            raise Sodium::Error.new("Invalid header or key")
          end
        end
      end

      # Pull a message from the encrypted stream
      def pull(ciphertext : Bytes, ad : Bytes? = nil) : {Bytes, Tag}
        raise ArgumentError.new("Ciphertext too short") if ciphertext.bytesize < ABYTES

        message = Bytes.new(ciphertext.bytesize - ABYTES)
        ad_ptr = ad ? ad.to_unsafe : Pointer(UInt8).null
        ad_len = ad ? ad.bytesize : 0_u64

        tag_value = uninitialized UInt8

        @state.readwrite do |state_slice|
          out_len = uninitialized UInt64
          if LibSodium.crypto_secretstream_xchacha20poly1305_pull(
               state_slice, message, pointerof(out_len),
               pointerof(tag_value), ciphertext, ciphertext.bytesize.to_u64,
               ad_ptr, ad_len
             ) != 0
            raise Sodium::Error.new("Decryption failed: corrupted or tampered data")
          end
        end

        {message, Tag.from_c(tag_value)}
      end

      # Rekey the stream (must match encryption rekey points)
      def rekey : Nil
        @state.readwrite do |state_slice|
          LibSodium.crypto_secretstream_xchacha20poly1305_rekey(state_slice)
        end
      end
    end
  end
end
