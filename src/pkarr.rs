//! Address directory: stores the signed address records ("pkarr" packets)
//! that endpoints publish, so that peers can find each other without
//! iroh's public directory (dns.iroh.link).
//!
//! Records are signed by the endpoint's key, so the store only checks the
//! signature and keeps the newest one. Endpoints republish every 5 minutes,
//! so nothing needs to survive a restart.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use iroh_base::PublicKey;
use iroh_dns::pkarr::SignedPacket;

/// Records not refreshed for this long are dropped.
const EXPIRY: Duration = Duration::from_secs(24 * 3600);

#[derive(Debug, PartialEq, Eq)]
pub enum PutError {
    /// Bad key or signature.
    Invalid,
    /// Older than the stored record.
    Outdated,
    /// The store holds `max_records` live records.
    Full,
}

/// A record in relay format signed by the key `z32`.
pub fn verify(z32: &str, payload: &[u8]) -> bool {
    PublicKey::from_z32(z32)
        .is_ok_and(|key| SignedPacket::from_relay_payload(&key, payload).is_ok())
}

pub struct Store {
    records: Mutex<HashMap<PublicKey, (SignedPacket, Instant)>>,
    max_records: usize,
}

impl Store {
    pub fn new(max_records: usize) -> Self {
        Store {
            records: Mutex::new(HashMap::new()),
            max_records,
        }
    }

    pub fn put(&self, z32: &str, payload: &[u8]) -> Result<(), PutError> {
        let key = PublicKey::from_z32(z32).map_err(|_| PutError::Invalid)?;
        let packet =
            SignedPacket::from_relay_payload(&key, payload).map_err(|_| PutError::Invalid)?;
        let mut records = self.records.lock().unwrap();
        match records.get(&key) {
            Some((old, _)) if old.timestamp() > packet.timestamp() => {
                return Err(PutError::Outdated);
            }
            None if records.len() >= self.max_records => {
                let now = Instant::now();
                records.retain(|_, (_, seen)| now.duration_since(*seen) < EXPIRY);
                if records.len() >= self.max_records {
                    return Err(PutError::Full);
                }
            }
            _ => {}
        }
        records.insert(key, (packet, Instant::now()));
        Ok(())
    }

    /// The stored record in relay format (signature, timestamp, DNS packet).
    pub fn get(&self, z32: &str) -> Option<Vec<u8>> {
        let key = PublicKey::from_z32(z32).ok()?;
        let records = self.records.lock().unwrap();
        let (packet, seen) = records.get(&key)?;
        (seen.elapsed() < EXPIRY).then(|| packet.to_relay_payload())
    }

    pub fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    pub fn prune(&self) {
        let now = Instant::now();
        self.records
            .lock()
            .unwrap()
            .retain(|_, (_, seen)| now.duration_since(*seen) < EXPIRY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_base::SecretKey;

    fn packet(secret: &SecretKey, value: &str) -> SignedPacket {
        SignedPacket::from_txt_strings(secret, "_iroh", [value], 30).unwrap()
    }

    #[test]
    fn keeps_newest_valid_record() {
        let store = Store::new(10);
        let secret = SecretKey::generate();
        let z32 = secret.public().to_z32();
        let old = packet(&secret, "relay=https://a/");
        let new = packet(&secret, "relay=https://b/");

        store.put(&z32, &new.to_relay_payload()).unwrap();
        assert_eq!(
            store.put(&z32, &old.to_relay_payload()),
            Err(PutError::Outdated)
        );
        assert_eq!(store.get(&z32).unwrap(), new.to_relay_payload());

        // Signed by someone else.
        let other = SecretKey::generate();
        let forged = packet(&other, "relay=https://evil/");
        assert_eq!(
            store.put(&z32, &forged.to_relay_payload()),
            Err(PutError::Invalid)
        );
        assert_eq!(store.put("not-a-key", b"x"), Err(PutError::Invalid));
    }

    #[test]
    fn refuses_new_keys_when_full() {
        let store = Store::new(1);
        let (a, b) = (SecretKey::generate(), SecretKey::generate());
        store
            .put(&a.public().to_z32(), &packet(&a, "x").to_relay_payload())
            .unwrap();
        assert_eq!(
            store.put(&b.public().to_z32(), &packet(&b, "x").to_relay_payload()),
            Err(PutError::Full)
        );
        // Updating a known key still works.
        store
            .put(&a.public().to_z32(), &packet(&a, "y").to_relay_payload())
            .unwrap();
    }
}
