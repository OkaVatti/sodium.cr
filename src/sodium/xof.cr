# src/sodium/xof.cr
require "./lib_sodium"
require "./secure_buffer"
require "./error"

module Sodium
  module XOF
    # Common base for all XOF primitives.
    abstract class Base
      @state : SecureBuffer
      @finalized = false

      def initialize
        @state = SecureBuffer.new(state_bytes)
        init_state
      end

      abstract def state_bytes : Int32
      abstract def low_level_update(state : Pointer(UInt8), data : Pointer(UInt8), len : UInt64) : Int32
      abstract def low_level_final(state : Pointer(UInt8), output : Pointer(UInt8), len : UInt64) : Int32
      abstract def init_state : Nil

      def update(data : String | Bytes) : self
        raise Sodium::Error.new("XOF already finalized") if @finalized
        @state.readwrite do |st|
          if low_level_update(st.to_unsafe, data.to_unsafe, data.bytesize.to_u64) != 0
            raise Sodium::Error.new("XOF update failed")
          end
        end
        self
      end

      def final(output_length : Int) : Bytes
        raise Sodium::Error.new("XOF already finalized") if @finalized
        output = Bytes.new(output_length)
        @state.readwrite do |st|
          if low_level_final(st.to_unsafe, output.to_unsafe, output_length.to_u64) != 0
            raise Sodium::Error.new("XOF finalization failed")
          end
        end
        @finalized = true
        output
      end
    end

    # SHAKE128 (no domain by default, but accepts :domain for advanced use)
    class Shake128 < Base
      @domain : UInt8?

      def initialize(domain : UInt8? = nil)
        @domain = domain
        super()
      end

      def state_bytes : Int32
        LibSodium.crypto_xof_shake128_statebytes.to_i32
      end

      def low_level_update(state : Pointer(UInt8), data : Pointer(UInt8), len : UInt64) : Int32
        LibSodium.crypto_xof_shake128_update(state, data, len)
      end

      def low_level_final(state : Pointer(UInt8), output : Pointer(UInt8), len : UInt64) : Int32
        LibSodium.crypto_xof_shake128_squeeze(state, output, len)
      end

      def init_state : Nil
        @state.readwrite do |st|
          if d = @domain
            if LibSodium.crypto_xof_shake128_init_with_domain(st.to_unsafe, d) != 0
              raise Sodium::Error.new("SHAKE128 init with domain failed")
            end
          else
            if LibSodium.crypto_xof_shake128_init(st.to_unsafe) != 0
              raise Sodium::Error.new("SHAKE128 initialization failed")
            end
          end
        end
      end

      def self.digest(data : String | Bytes, output_length : Int, domain : UInt8? = nil) : Bytes
        xof = new(domain)
        xof.update(data)
        xof.final(output_length)
      end
    end

    # SHAKE256 (optional domain)
    class Shake256 < Base
      @domain : UInt8?

      def initialize(domain : UInt8? = nil)
        @domain = domain
        super()
      end

      def state_bytes : Int32
        LibSodium.crypto_xof_shake256_statebytes.to_i32
      end

      def low_level_update(state : Pointer(UInt8), data : Pointer(UInt8), len : UInt64) : Int32
        LibSodium.crypto_xof_shake256_update(state, data, len)
      end

      def low_level_final(state : Pointer(UInt8), output : Pointer(UInt8), len : UInt64) : Int32
        LibSodium.crypto_xof_shake256_squeeze(state, output, len)
      end

      def init_state : Nil
        @state.readwrite do |st|
          if d = @domain
            if LibSodium.crypto_xof_shake256_init_with_domain(st.to_unsafe, d) != 0
              raise Sodium::Error.new("SHAKE256 init with domain failed")
            end
          else
            if LibSodium.crypto_xof_shake256_init(st.to_unsafe) != 0
              raise Sodium::Error.new("SHAKE256 initialization failed")
            end
          end
        end
      end

      def self.digest(data : String | Bytes, output_length : Int, domain : UInt8? = nil) : Bytes
        xof = new(domain)
        xof.update(data)
        xof.final(output_length)
      end
    end

    # TurboSHAKE128 with mandatory domain (0..255)
    class TurboShake128 < Base
      @domain : UInt8

      def initialize(domain : UInt8 = 0_u8)
        @domain = domain
        super()
      end

      def state_bytes : Int32
        LibSodium.crypto_xof_turboshake128_statebytes.to_i32
      end

      def low_level_update(state : Pointer(UInt8), data : Pointer(UInt8), len : UInt64) : Int32
        LibSodium.crypto_xof_turboshake128_update(state, data, len)
      end

      def low_level_final(state : Pointer(UInt8), output : Pointer(UInt8), len : UInt64) : Int32
        LibSodium.crypto_xof_turboshake128_squeeze(state, output, len)
      end

      def init_state : Nil
        @state.readwrite do |st|
          if LibSodium.crypto_xof_turboshake128_init_with_domain(st.to_unsafe, @domain) != 0
            raise Sodium::Error.new("TurboSHAKE128 init failed")
          end
        end
      end

      def self.digest(data : String | Bytes, output_length : Int, domain : UInt8 = 0_u8) : Bytes
        xof = new(domain)
        xof.update(data)
        xof.final(output_length)
      end
    end

    # TurboSHAKE256 with mandatory domain
    class TurboShake256 < Base
      @domain : UInt8

      def initialize(domain : UInt8 = 0_u8)
        @domain = domain
        super()
      end

      def state_bytes : Int32
        LibSodium.crypto_xof_turboshake256_statebytes.to_i32
      end

      def low_level_update(state : Pointer(UInt8), data : Pointer(UInt8), len : UInt64) : Int32
        LibSodium.crypto_xof_turboshake256_update(state, data, len)
      end

      def low_level_final(state : Pointer(UInt8), output : Pointer(UInt8), len : UInt64) : Int32
        LibSodium.crypto_xof_turboshake256_squeeze(state, output, len)
      end

      def init_state : Nil
        @state.readwrite do |st|
          if LibSodium.crypto_xof_turboshake256_init_with_domain(st.to_unsafe, @domain) != 0
            raise Sodium::Error.new("TurboSHAKE256 init failed")
          end
        end
      end

      def self.digest(data : String | Bytes, output_length : Int, domain : UInt8 = 0_u8) : Bytes
        xof = new(domain)
        xof.update(data)
        xof.final(output_length)
      end
    end
  end
end
