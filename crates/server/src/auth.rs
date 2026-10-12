use anyhow::{Result, ensure};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::RngCore;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

pub fn token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
#[derive(Clone)]
pub struct Session {
    pub csrf: String,
    pub expires: Instant,
}
pub struct Auth {
    hash: String,
    sessions: Mutex<HashMap<String, Session>>,
    attempts: Mutex<HashMap<IpAddr, (Instant, u32)>>,
    global: Mutex<(Instant, u32)>,
    slots: Arc<Semaphore>,
}
impl Auth {
    pub fn new(password: &str) -> Result<Self> {
        ensure!(
            password.len() >= 12 && password.len() <= 1024,
            "administrator password must have 12–1024 bytes"
        );
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))?
            .to_string();
        Ok(Self {
            hash,
            sessions: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::new()),
            global: Mutex::new((Instant::now(), 0)),
            slots: Arc::new(Semaphore::new(2)),
        })
    }
    pub fn session(&self, id: &str) -> Option<Session> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.expires > Instant::now());
        sessions.get(id).cloned()
    }
    pub async fn login(&self, ip: IpAddr, password: String) -> Option<(String, String)> {
        if password.len() > 1024 {
            return None;
        }
        {
            let mut g = self.global.lock().unwrap();
            if g.0.elapsed() > Duration::from_secs(60) {
                *g = (Instant::now(), 0);
            }
            if g.1 >= 20 {
                return None;
            }
            g.1 += 1;
        }
        {
            let mut a = self.attempts.lock().unwrap();
            a.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(60));
            if !a.contains_key(&ip) && a.len() >= 1024 {
                return None;
            }
            let v = a.entry(ip).or_insert((Instant::now(), 0));
            if v.1 >= 5 {
                return None;
            }
            v.1 += 1;
        }
        let permit = self.slots.clone().try_acquire_owned().ok()?;
        let hash = self.hash.clone();
        let valid = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            PasswordHash::new(&hash).is_ok_and(|h| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &h)
                    .is_ok()
            })
        })
        .await
        .ok()?;
        if !valid {
            return None;
        }
        let id = token();
        let csrf = token();
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.expires > Instant::now());
        if sessions.len() >= 64 {
            return None;
        }
        sessions.insert(
            id.clone(),
            Session {
                csrf: csrf.clone(),
                expires: Instant::now() + Duration::from_secs(12 * 3600),
            },
        );
        Some((id, csrf))
    }
    pub fn logout(&self, id: &str) {
        self.sessions.lock().unwrap().remove(id);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn password_sessions_and_rate_limit() {
        let a = Auth::new("a strong test password").unwrap();
        let ip = "127.0.0.1".parse().unwrap();
        assert!(a.login(ip, "wrong".into()).await.is_none());
        let (id, csrf) = a.login(ip, "a strong test password".into()).await.unwrap();
        assert_eq!(a.session(&id).unwrap().csrf, csrf);
        a.logout(&id);
        assert!(a.session(&id).is_none());
        for _ in 0..5 {
            a.login(ip, "wrong".into()).await;
        }
        assert!(a.login(ip, "a strong test password".into()).await.is_none());
    }
}
