# src/sodium/password/abstract.cr
module Sodium::Password
  abstract class Abstract
    @ops : UInt64 = 0_u64
    @mem : UInt64 = 0_u64

    def ops : UInt64
      @ops
    end

    def ops=(@ops : UInt64) : UInt64
    end

    def mem : UInt64
      @mem
    end

    def mem=(@mem : UInt64) : UInt64
    end

    SALT_SIZE = LibSodium.crypto_pwhash_saltbytes.to_i

    def random_salt : Bytes
      salt = Bytes.new(SALT_SIZE)
      LibSodium.randombytes_buf(salt, SALT_SIZE)
      salt
    end

    def self.from_params(hash)
      pw = self.new

      pw.ops = hash["ops"].as(UInt64)
      pw.mem = hash["mem"].as(UInt64)

      if pw.responds_to?(:mode=) && (mode = hash["mode"]?)
        pw.mode = Mode.parse mode.as(String)
      end
      if pw.responds_to?(:salt=) && (salt = hash["salt"]?)
        pw.salt = salt.as(Bytes)
      end
      if pw.responds_to?(:key_size=) && (key_size = hash["key_size"]?)
        pw.key_size = key_size.as(Int32)
      end
      if pw.responds_to?(:tcost=) && (tcost = hash["tcost"]?)
        pw.tcost = tcost.as(Float64)
      end
      if pw.responds_to?(:verify=) && (verify = hash["verify"]?)
        pw.verify = verify.as(Bytes)
      end

      pw
    end
  end
end
