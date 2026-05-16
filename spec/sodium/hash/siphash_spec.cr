# spec/sodium/hash/siphash_spec.cr
require "../../spec_helper"
require "../../../src/sodium/hash/siphash"

describe Sodium::Hash::SipHash do
  it "computes a SipHash" do
    key = Random::Secure.random_bytes(Sodium::Hash::SipHash::KEY_BYTES)
    hash = Sodium::Hash::SipHash.digest("test", key)
    hash.bytesize.should eq Sodium::Hash::SipHash::BYTES
    hash.should_not eq Bytes.new(8, 0_u8)
  end

  it "produces deterministic output" do
    key = "000102030405060708090a0b0c0d0e0f".hexbytes
    data = "hello SipHash"
    hash1 = Sodium::Hash::SipHash.digest(data, key)
    hash2 = Sodium::Hash::SipHash.digest(data, key)
    hash1.should eq hash2
    hash3 = Sodium::Hash::SipHash.digest("other data", key)
    hash1.should_not eq hash3
  end
end
