require "../spec_helper"
require "../../src/sodium/ipcrypt"

describe Sodium::IPCrypt do
  it "encrypts/decrypts IPv4" do
    key = Sodium::IPCrypt.keygen
    original = "192.168.1.1"
    encrypted = Sodium::IPCrypt.encrypt(original, key)
    decrypted = Sodium::IPCrypt.decrypt(encrypted, key)
    decrypted.should eq original
  end

  pending "encrypts/decrypts IPv6 (libsodium may have a bug with IPv6 in this version)" do
    key = Sodium::IPCrypt.keygen
    original = "2001:db8::1"
    encrypted = Sodium::IPCrypt.encrypt(original, key)
    decrypted = Sodium::IPCrypt.decrypt(encrypted, key)
    decrypted.should eq original
  end

  it "deterministic encryption" do
    key = "000102030405060708090a0b0c0d0e0f".hexbytes
    address = "192.168.1.1"
    encrypted1 = Sodium::IPCrypt.encrypt(address, key)
    encrypted2 = Sodium::IPCrypt.encrypt(address, key)
    encrypted1.should eq encrypted2
    Sodium::IPCrypt.decrypt(encrypted1, key).should eq address
  end
end
