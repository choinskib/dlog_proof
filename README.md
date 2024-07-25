# DLog Proof

This project implements a Non-interactive Schnorr ZK DLOG Proof scheme with a Fiat-Shamir transformation proof system using the `k256` elliptic curve library. The proof system allows for the creation and verification of DLog proofs, as well as serialization and deserialization of proofs.

## Files

- `main.rs`: Contains the main function that demonstrates the creation, serialization, deserialization, and verification of a DLog proof.
- `lib.rs`: Contains the implementation of the DLog proof system, including the `DLogProof` struct and associated methods.

## Usage

### main.rs

The `main.rs` file demonstrates the following steps:

1. Generate a random scalar `x`.
2. Compute the elliptic curve point `y = G * x`, where `G` is the generator point.
3. Create a DLog proof for `x` and `y`.
4. Serialize the proof to a JSON string.
5. Deserialize the proof from the JSON string.
6. Verify the proof.