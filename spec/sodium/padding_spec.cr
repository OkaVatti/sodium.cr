require "../spec_helper"
require "../../src/sodium/padding"

describe Sodium::Padding do
  it "pads and unpads a message" do
    original = "hello".to_slice
    padded = Sodium::Padding.pad(original, block_size: 64)
    (padded.bytesize % 64).should eq 0
    padded.bytesize.should be >= original.bytesize
    unpadded = Sodium::Padding.unpad(padded, block_size: 64)
    unpadded.should eq original
  end

  it "roundtrips with various block sizes" do
    [16, 32, 64, 128].each do |bs|
      msg = "test message"
      padded = Sodium::Padding.pad(msg.to_slice, block_size: bs)
      unpadded = Sodium::Padding.unpad(padded, block_size: bs)
      unpadded.should eq msg.to_slice
    end
  end

  it "passes official test vector" do
    original = "0123456789abcdef".to_slice
    block_size = 16
    # pad with 0x80 followed by zeros to reach the next block boundary
    expected_padded = original + Bytes[0x80_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8,
      0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8]
    padded = Sodium::Padding.pad(original, block_size: 16)
    padded.should eq expected_padded
    Sodium::Padding.unpad(padded, block_size: 16).should eq original
  end
end
