use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgConnection;

type HmacSha256 = Hmac<Sha256>;

const PREFIX: &str = "$bcrypt-sha256$";

struct ParsedHash<'a> {
    cost: u32,
    salt: &'a str,
    checksum: &'a str,
}

pub(crate) async fn hash_password(
    connection: &mut PgConnection,
    password: &str,
) -> Result<String, sqlx::Error> {
    let native_salt = sqlx::query_scalar::<_, String>("SELECT public.gen_salt('bf', 12)")
        .fetch_one(&mut *connection)
        .await?;
    let salt = native_salt
        .rsplit_once('$')
        .map(|(_, salt)| salt)
        .filter(|salt| salt.len() == 22)
        .ok_or_else(|| sqlx::Error::Protocol("pgcrypto returned an invalid bcrypt salt".into()))?;
    let prehashed = prehash(password, salt);
    let native_hash = sqlx::query_scalar::<_, String>("SELECT public.crypt($1, $2)")
        .bind(prehashed)
        .bind(&native_salt)
        .fetch_one(&mut *connection)
        .await?;
    let checksum = native_hash
        .rsplit_once('$')
        .and_then(|(_, body)| body.get(22..))
        .filter(|checksum| checksum.len() == 31)
        .ok_or_else(|| sqlx::Error::Protocol("pgcrypto returned an invalid bcrypt hash".into()))?;

    Ok(format!("{PREFIX}v=2,t=2b,r=12${salt}${checksum}"))
}

pub(crate) async fn verify_password(
    connection: &mut PgConnection,
    password: &str,
    encoded: &str,
) -> Result<bool, sqlx::Error> {
    let Some(parsed) = parse(encoded) else {
        return Ok(false);
    };
    let native_hash = format!("$2a${:02}${}{}", parsed.cost, parsed.salt, parsed.checksum);
    sqlx::query_scalar::<_, bool>("SELECT public.crypt($1, $2) = $2")
        .bind(prehash(password, parsed.salt))
        .bind(native_hash)
        .fetch_one(connection)
        .await
}

fn parse(encoded: &str) -> Option<ParsedHash<'_>> {
    let encoded = encoded.strip_prefix(PREFIX)?;
    let mut fields = encoded.split('$');
    let parameters = fields.next()?;
    let salt = fields.next()?;
    let checksum = fields.next()?;
    if fields.next().is_some() || salt.len() != 22 || checksum.len() != 31 {
        return None;
    }
    let cost = parameters.strip_prefix("v=2,t=2b,r=")?.parse().ok()?;
    Some(ParsedHash {
        cost,
        salt,
        checksum,
    })
}

fn prehash(password: &str, encoded_salt: &str) -> String {
    let mut digest = HmacSha256::new_from_slice(encoded_salt.as_bytes())
        .expect("HMAC-SHA256 accepts keys of every length");
    digest.update(password.as_bytes());
    STANDARD.encode(digest.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PYTHON_FIXTURE: &str =
        "$bcrypt-sha256$v=2,t=2b,r=4$abcdefghijklmnopqrstuu$h8GCYhBqatMGV8VIjRD4nhRxM87r3yu";

    #[test]
    fn parses_passlib_bcrypt_sha256_fixture() {
        let parsed = parse(PYTHON_FIXTURE).unwrap();
        assert_eq!(parsed.cost, 4);
        assert_eq!(parsed.salt, "abcdefghijklmnopqrstuu");
        assert_eq!(parsed.checksum, "h8GCYhBqatMGV8VIjRD4nhRxM87r3yu");
    }

    #[test]
    fn rejects_non_passlib_hashes() {
        assert!(parse("$2b$12$abcdefghijklmnopqrstuu0123456789012345678901234567890").is_none());
        assert!(parse("$bcrypt-sha256$v=1,t=2b,r=12$bad$bad").is_none());
    }
}
