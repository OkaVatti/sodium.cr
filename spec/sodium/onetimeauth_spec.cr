require "../spec_helper"
require "../../src/sodium/onetimeauth"

describe Sodium::OneTimeAuth do
  it "computes and verifies a tag" do
    key = Random::Secure.random_bytes(Sodium::OneTimeAuth::KEY_BYTES)
    message = "hello world"
    tag = Sodium::OneTimeAuth.tag(message, key)
    tag.bytesize.should eq Sodium::OneTimeAuth::BYTES
    Sodium::OneTimeAuth.verify(message, tag, key).should be_true
    Sodium::OneTimeAuth.verify("wrong", tag, key).should be_false
    Sodium::OneTimeAuth.verify(message, Bytes.new(Sodium::OneTimeAuth::BYTES, 0_u8), key).should be_false
  end

  it "produces deterministic tags" do
    key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".hexbytes
    msg = "test"
    tag1 = Sodium::OneTimeAuth.tag(msg, key)
    tag2 = Sodium::OneTimeAuth.tag(msg, key)
    tag1.should eq tag2
  end
end
