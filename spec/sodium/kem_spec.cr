# spec/sodium/kem_spec.cr
require "../spec_helper"
require "../../src/sodium/kem"

describe Sodium::KEM do
  it "encapsulates and decapsulates a shared secret" do
    bob = Sodium::KEM::KeyPair.new
    ciphertext, alice_ss = Sodium::KEM.encapsulate(bob.public_key)
    bob_ss = Sodium::KEM.decapsulate(ciphertext, bob)
    alice_ss.should eq(bob_ss)
  end

  it "works with deterministic key generation" do
    seed = Random::Secure.random_bytes(Sodium::KEM::SEED_BYTES)
    keypair1 = Sodium::KEM::KeyPair.new(seed)
    keypair2 = Sodium::KEM::KeyPair.new(seed)
    keypair1.public_key.should eq(keypair2.public_key)
  end

  it "MLKEM768 also works correctly" do
    bob = Sodium::KEM::MLKEM768::KeyPair.new
    ciphertext, alice_ss = Sodium::KEM::MLKEM768.encapsulate(bob.public_key)
    bob_ss = Sodium::KEM::MLKEM768.decapsulate(ciphertext, bob)
    alice_ss.should eq(bob_ss)
  end

  it "produces a different shared secret with a random ciphertext" do
    bob = Sodium::KEM::KeyPair.new
    ciphertext, original_ss = Sodium::KEM.encapsulate(bob.public_key)
    fake_ss = Sodium::KEM.decapsulate(Random::Secure.random_bytes(Sodium::KEM::CIPHERTEXT_BYTES), bob)
    fake_ss.should_not eq(original_ss)
  end
end
