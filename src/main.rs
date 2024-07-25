
use std::time::Instant;

use k256::elliptic_curve::point::AffineCoordinates;
use k256::ProjectivePoint;

use dlog_proof::{DLogProof, generate_random_number};

fn main() {
    let sid = "sid";
    let pid = 1u64;

    let x = generate_random_number();
    println!("x: {:?}", x);

    let y = ProjectivePoint::GENERATOR * x;

    let start_proof = Instant::now();
    let dlog_proof = DLogProof::prove(sid, pid, x, y).expect("Failed to create proof");
    let proof_duration = start_proof.elapsed();
    println!("Proof computation time: {} ms", proof_duration.as_millis());

    // Serialize the proof
    let serialized = serde_json::to_string(&dlog_proof).unwrap();
    println!("Serialized proof: {}", serialized);

    // Deserialize the proof
    let deserialized: DLogProof = serde_json::from_str(&serialized).unwrap();
    println!("Deserialized proof: {:?}/n", deserialized);

    assert_eq!(dlog_proof, deserialized);

    println!("t.x: {:?}", dlog_proof.t().to_affine().x());
    // The y-coordinate of the point is not accessible directly
    println!("t.y: {:?}", dlog_proof.t().to_affine().y_is_odd());
    println!("s: {:?}", dlog_proof.s());

    let start_verify = Instant::now();
    let result = dlog_proof
        .verify(sid, pid, y)
        .expect("Failed to verify proof");
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
