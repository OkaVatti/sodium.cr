require "../../spec_helper"
require "../../../src/sodium/sign/pre_hashed"

describe Sodium::Sign::PreHashed do
  it "matches RFC 8032 Ed25519ph test vector" do
    # From RFC 8032, Section 7.3 – message "abc"
    seed_hex = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
    pk_hex = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
    message = "abc"
    sig_hex = "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41" \
              "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406"

    sk = Sodium::Sign::SecretKey.new(seed: seed_hex.hexbytes)
    pk = Sodium::Sign::PublicKey.new(pk_hex.hexbytes)

    state = Sodium::Sign::PreHashed.new
    state.update(message)
    sig = state.sign(sk)
    sig.should eq sig_hex.hexbytes

    # Verification with the correct message/public key
    vstate = Sodium::Sign::PreHashed.new
    vstate.update(message)
    vstate.verify(sig, pk) # no exception

    # Tampered message must fail
    vstate2 = Sodium::Sign::PreHashed.new
    vstate2.update("wrong")
    expect_raises(Sodium::Error::VerificationFailed) do
      vstate2.verify(sig, pk)
    end
  end
end
