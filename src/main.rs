use k256::{
    elliptic_curve::{
        group::{GroupEncoding},
        Field, Scalar, PrimeField,
        generic_array::GenericArray,
    },
    ProjectivePoint, Secp256k1,    
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use hex;
use typenum::U33;

// Generate a random number
fn generate_random_number() -> Scalar<Secp256k1> {
    let mut rng = OsRng;
    Scalar::<Secp256k1>::random(&mut rng)
}

struct DLogProof {
    t: ProjectivePoint,
    s: Scalar<Secp256k1>,
}

impl PartialEq for DLogProof {
    fn eq(&self, other: &Self) -> bool {
        self.t == other.t && self.s == other.s
    }
}

impl Eq for DLogProof {}

impl DLogProof {
    fn hash_points(sid: &str, pid: u64, points: &[ProjectivePoint]) -> Scalar<Secp256k1> {
        let mut hasher = Sha256::new();
        hasher.update(sid.as_bytes());
        hasher.update(pid.to_le_bytes());
        for point in points {
            let encoded_point = point.to_encoded_point(true);
            hasher.update(encoded_point.as_bytes());
        }
        let result = hasher.finalize();
        Scalar::<Secp256k1>::from_repr(GenericArray::clone_from_slice(&result)).unwrap()
    }

    fn prove(sid: &str, pid: u64, x: Scalar<Secp256k1>, y: ProjectivePoint) -> Self {
        let r = generate_random_number();
        let t = ProjectivePoint::GENERATOR * r;
        let c = Self::hash_points(sid, pid, &[ProjectivePoint::GENERATOR, y, t]);
        let s = r + c * x;
        Self { t, s }
    }

    fn verify(&self, sid: &str, pid: u64, y: ProjectivePoint) -> bool {
        let c = Self::hash_points(sid, pid, &[ProjectivePoint::GENERATOR, y, self.t]);
        let lhs = ProjectivePoint::GENERATOR * self.s;
        let rhs = self.t + (y * c);
        lhs == rhs
    }

    fn to_dict(&self) -> (String, String) {
        let t_bytes = self.t.to_bytes().to_vec();
        let s_bytes = self.s.to_bytes().to_vec();
        (hex::encode(t_bytes), hex::encode(s_bytes))
    }

    fn from_dict(data: (String, String)) -> Self {
        let t_bytes_vec = hex::decode(data.0).unwrap();
        let t_bytes: GenericArray<u8, U33> = GenericArray::clone_from_slice(&t_bytes_vec);
        let s_bytes = hex::decode(data.1).unwrap();
        let t = ProjectivePoint::from_bytes(&t_bytes).unwrap();
        let s = Scalar::<Secp256k1>::from_repr(GenericArray::clone_from_slice(&s_bytes)).unwrap();
        Self { t, s }
    }
}

fn main() {
    let sid = "sid";
    let pid = 1u64;

    let x = generate_random_number();
    println!("x: {:?}", x);

    let y = ProjectivePoint::GENERATOR * x;

    let start_proof = Instant::now();
    let dlog_proof = DLogProof::prove(sid, pid, x, y);
    let proof_duration = start_proof.elapsed();
    println!(
        "Proof computation time: {} ms",
        proof_duration.as_millis()
    );

    println!("");
    println!("s: {:?}", dlog_proof.s);

    let start_verify = Instant::now();
    let result = dlog_proof.verify(sid, pid, y);
    let verify_duration = start_verify.elapsed();
    println!(
        "Verify computation time: {} ms",
        verify_duration.as_millis()
    );

    if result {
        println!("DLOG proof is correct");
    } else {
        println!("DLOG proof is not correct");
    }
}
