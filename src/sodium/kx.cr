# src/sodium/kx.cr
require "./lib_sodium"
require "./secure_buffer"
require "./error"

module Sodium
  # Implements libsodium's crypto_kx API for secure key exchange.
  #
  # Usage:
  #   client = KX::Client.new
  #   server = KX::Server.new
  #   client.session_keys(server.public_key) # => {rx, tx}
  #   server.session_keys(client.public_key) # => {rx, tx} (note reversed role)
  module KX
    # Sizes in bytes
    PUBLIC_KEY_BYTES  = LibSodium.crypto_kx_publickeybytes.to_i
    SECRET_KEY_BYTES  = LibSodium.crypto_kx_secretkeybytes.to_i
    SEED_BYTES        = LibSodium.crypto_kx_seedbytes.to_i
    SESSION_KEY_BYTES = LibSodium.crypto_kx_sessionkeybytes.to_i

    # Represents a key exchange participant.
    abstract class Participant
      getter public_key : Bytes
      getter secret_key : SecureBuffer

      def initialize
        @public_key = Bytes.new(PUBLIC_KEY_BYTES)
        @secret_key = SecureBuffer.new(SECRET_KEY_BYTES)
      end

      # Generate a new key pair.
      protected def generate_keypair
        secret_key.readwrite do |sk|
          if LibSodium.crypto_kx_keypair(public_key, sk) != 0
            raise Sodium::Error.new("crypto_kx_keypair failed")
          end
        end
      end

      # Generate a key pair from a deterministic seed.
      protected def generate_keypair(seed : Bytes)
        secret_key.readwrite do |sk|
          if LibSodium.crypto_kx_seed_keypair(public_key, sk, seed) != 0
            raise Sodium::Error.new("crypto_kx_seed_keypair failed")
          end
        end
      end
    end

    # Client-side key exchange.
    class Client < Participant
      def initialize
        super
        generate_keypair
      end

      def initialize(seed : Bytes)
        raise ArgumentError.new("Seed must be #{SEED_BYTES} bytes") unless seed.bytesize == SEED_BYTES
        super()
        generate_keypair(seed)
      end

      # Compute session keys using the server's public key.
      # Returns a tuple `{rx, tx}` where `rx` is for receiving data from the server,
      # and `tx` is for sending data to the server.
      def session_keys(server_public_key : Bytes) : {Bytes, Bytes}
        rx = Bytes.new(SESSION_KEY_BYTES)
        tx = Bytes.new(SESSION_KEY_BYTES)
        secret_key.readonly do |sk|
          if LibSodium.crypto_kx_client_session_keys(rx, tx, public_key, sk, server_public_key) != 0
            raise Sodium::Error.new("crypto_kx_client_session_keys failed (bad server public key?)")
          end
        end
        {rx, tx}
      end
    end

    # Server-side key exchange.
    class Server < Participant
      def initialize
        super
        generate_keypair
      end

      def initialize(seed : Bytes)
        raise ArgumentError.new("Seed must be #{SEED_BYTES} bytes") unless seed.bytesize == SEED_BYTES
        super()
        generate_keypair(seed)
      end

      # Compute session keys using the client's public key.
      # Returns a tuple `{rx, tx}` where `rx` is for receiving data from the client,
      # and `tx` is for sending data to the client.
      def session_keys(client_public_key : Bytes) : {Bytes, Bytes}
        rx = Bytes.new(SESSION_KEY_BYTES)
        tx = Bytes.new(SESSION_KEY_BYTES)
        secret_key.readonly do |sk|
          if LibSodium.crypto_kx_server_session_keys(rx, tx, public_key, sk, client_public_key) != 0
            raise Sodium::Error.new("crypto_kx_server_session_keys failed (bad client public key?)")
          end
        end
        {rx, tx}
      end
    end
  end
end
