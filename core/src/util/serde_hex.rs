//! Hex serialization helpers for serde
use serde::{Serialize, Deserialize};

pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    hex::decode(s).map_err(serde::de::Error::custom)
}

pub mod x25519 {
    use super::*;
    use x25519_dalek::PublicKey;
    pub fn serialize<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(key.as_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| serde::de::Error::custom("Invalid length"))?;
        Ok(PublicKey::from(array))
    }
}

pub mod verifying_key {
    use super::*;
    use ed25519_dalek::VerifyingKey;
    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(key.as_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| serde::de::Error::custom("Invalid length"))?;
        VerifyingKey::from_bytes(&array).map_err(serde::de::Error::custom)
    }
}

pub mod signature {
    use super::*;
    use ed25519_dalek::Signature;
    pub fn serialize<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(sig.to_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        let array: [u8; 64] = bytes.try_into().map_err(|_| serde::de::Error::custom("Invalid length"))?;
        Ok(Signature::from_bytes(&array))
    }
}

pub mod otpk {
    use super::*;
    use x25519_dalek::PublicKey;
    
    #[derive(Serialize, Deserialize)]
    struct OtpkInternal(u32, #[serde(with = "crate::util::serde_hex::x25519")] PublicKey);

    pub fn serialize<S>(otpk: &Option<(u32, PublicKey)>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match otpk {
            Some((id, key)) => OtpkInternal(*id, *key).serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<(u32, PublicKey)>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let opt = Option::<OtpkInternal>::deserialize(deserializer)?;
        Ok(opt.map(|OtpkInternal(id, key)| (id, key)))
    }
}
