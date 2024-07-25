use serde::{Deserialize, Deserializer, Serialize, Serializer};

use k256::{
    elliptic_curve::{
        generic_array::GenericArray, group::GroupEncoding, sec1::ToEncodedPoint, Field, PrimeField,
        Scalar,
    },
    ProjectivePoint, Secp256k1,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

pub fn generate_random_number() -> Scalar<Secp256k1> {
    let mut rng = OsRng;
    Scalar::<Secp256k1>::random(&mut rng)
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DLogProof {
    #[serde(
        serialize_with = "serialize_projective_point",
        deserialize_with = "deserialize_projective_point"
    )]
    t: ProjectivePoint,
    #[serde(
        serialize_with = "serialize_scalar",
        deserialize_with = "deserialize_scalar"
    )]
    s: Scalar<Secp256k1>,
}

fn serialize_projective_point<S>(t: &ProjectivePoint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let t_hex = hex::encode(t.to_bytes());
    serializer.serialize_str(&t_hex)
}

fn deserialize_projective_point<'de, D>(deserializer: D) -> Result<ProjectivePoint, D::Error>
where
    D: Deserializer<'de>,
{
    let t_hex: String = Deserialize::deserialize(deserializer)?;
    let t_bytes = hex::decode(t_hex).map_err(serde::de::Error::custom)?;
    let point = ProjectivePoint::from_bytes(&GenericArray::clone_from_slice(&t_bytes)).unwrap();
    Ok(point)
}

fn serialize_scalar<S>(s: &Scalar<Secp256k1>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s_bytes = s.to_bytes().to_vec();
    let s_hex = hex::encode(s_bytes);
    serializer.serialize_str(&s_hex)
}

fn deserialize_scalar<'de, D>(deserializer: D) -> Result<Scalar<Secp256k1>, D::Error>
where
    D: Deserializer<'de>,
{
    let s_hex: String = Deserialize::deserialize(deserializer)?;
    let s_bytes = hex::decode(s_hex).map_err(serde::de::Error::custom)?;
    Scalar::<Secp256k1>::from_repr(GenericArray::clone_from_slice(&s_bytes))
        .into_option()
        .ok_or_else(|| serde::de::Error::custom("Invalid scalar"))
}

impl DLogProof {
    pub fn hash_points(
        sid: &str,
        pid: u64,
        points: &[ProjectivePoint],
    ) -> Result<Scalar<Secp256k1>, anyhow::Error> {
        let result = points
            .iter()
            .fold(
                Sha256::new()
                    .chain_update(sid.as_bytes())
                    .chain_update(pid.to_le_bytes()),
                |mut hasher, point| {
                    hasher.update(point.to_encoded_point(true).as_bytes());
                    hasher
                },
            )
            .finalize();

        Scalar::<Secp256k1>::from_repr(GenericArray::clone_from_slice(&result))
            .into_option()
            .ok_or_else(|| anyhow::Error::msg("Failed to create scalar from hash"))
    }

    pub fn prove(
        sid: &str,
        pid: u64,
        x: Scalar<Secp256k1>,
        y: ProjectivePoint,
    ) -> Result<Self, anyhow::Error> {
        let r = generate_random_number();
        Ok(Self {
            t: ProjectivePoint::GENERATOR * r,
            s: r + x * Self::hash_points(
                sid,
                pid,
                &[
                    ProjectivePoint::GENERATOR,
                    y,
                    ProjectivePoint::GENERATOR * r,
                ],
            )?,
        })
    }

    pub fn verify(&self, sid: &str, pid: u64, y: ProjectivePoint) -> Result<bool, anyhow::Error> {
        let c = Self::hash_points(sid, pid, &[ProjectivePoint::GENERATOR, y, self.t])?;
        Ok(ProjectivePoint::GENERATOR * self.s == self.t + (y * c))
    }

    pub fn t(&self) -> &ProjectivePoint {
        &self.t
    }

    pub fn s(&self) -> &Scalar<Secp256k1> {
        &self.s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlog_proof() {
        let sid = "sid";
        let pid = 1u64;

        let x = generate_random_number();
        let y = ProjectivePoint::GENERATOR * x;

        let dlog_proof = DLogProof::prove(sid, pid, x, y).expect("Failed to create proof");

        assert!(dlog_proof.verify(sid, pid, y).expect("Failed to verify proof"));
    }

    #[test]
    fn test_dlog_proof_invalid() {
        let sid = "sid";
        let pid = 1u64;

        let x = generate_random_number();
        let y = ProjectivePoint::GENERATOR * x;

        let dlog_proof = DLogProof::prove(sid, pid, x, y).expect("Failed to create proof");

        let y_invalid = ProjectivePoint::GENERATOR * generate_random_number();

        assert!(!dlog_proof
            .verify(sid, pid, y_invalid)
            .expect("Failed to verify proof"));
    }

    #[test]
    fn test_dlog_proof_serialization() {
        let sid = "sid";
        let pid = 1u64;

        let x = generate_random_number();
        let y = ProjectivePoint::GENERATOR * x;

        let dlog_proof = DLogProof::prove(sid, pid, x, y).expect("Failed to create proof");

        let serialized = serde_json::to_string(&dlog_proof).unwrap();
        let deserialized: DLogProof = serde_json::from_str(&serialized).unwrap();

        assert_eq!(dlog_proof, deserialized);
    }
}