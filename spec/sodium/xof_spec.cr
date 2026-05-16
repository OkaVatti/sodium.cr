# spec/sodium/xof_spec.cr
require "../spec_helper"

describe Sodium::XOF do
  it "SHAKE128 produces expected output" do
    # Verified against libsodium's test/default/xof.c
    expected = Bytes[0xd3, 0xb0, 0xaa, 0x9c, 0xd8, 0xb7, 0x25, 0x56,
      0x22, 0xce, 0xbc, 0x63, 0x1e, 0x86, 0x7d, 0x40]
    output = Sodium::XOF::Shake128.digest("test", 16)
    output.should eq(expected)
  end

  it "streaming and one-shot produce the same result" do
    data = "hello world"
    one_shot = Sodium::XOF::Shake256.digest(data, 32)
    streaming = begin
      xof = Sodium::XOF::Shake256.new
      xof.update("hello ")
      xof.update("world")
      xof.final(32)
    end
    one_shot.should eq(streaming)
  end

  it "TurboSHAKE with different domains gives different outputs" do
    data = "msg"
    out0 = Sodium::XOF::TurboShake128.digest(data, 32, domain: 0_u8)
    out1 = Sodium::XOF::TurboShake128.digest(data, 32, domain: 1_u8)
    out0.should_not eq(out1)
  end
end
