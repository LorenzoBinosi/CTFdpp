use hmac::{Hmac, Mac};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::error::ApiError;

type HmacSha256 = Hmac<Sha256>;

pub(super) const RANDOM_TOKEN_PLACEHOLDER: &str = "{{RANDOM_TOKEN}}";
const MAX_FLAG_BYTES: usize = 512;
const MAX_REGEX_BYTES: usize = 512;
const MAX_LEET_POSITIONS: usize = 62;
const GENERATED_FLAG_LOCK_NAMESPACE: i32 = 0x464C_4147;
const CHALLENGE_FLAG_LOCK_NAMESPACE: i32 = 0x4346_4C47;
const MATCH_TAG_CONTEXT: &[u8] = b"ctfzone/generated-flag-match/v1";

#[derive(Clone, Debug, Deserialize)]
pub(super) struct InitialFlagInput {
    #[serde(rename = "type")]
    pub(super) flag_type: String,
    pub(super) content: String,
    #[serde(default = "empty_object")]
    pub(super) data: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct FlagPolicyData {
    pub(super) case_sensitive: bool,
    pub(super) leet_variation: bool,
    #[serde(alias = "accept_shared_flags")]
    pub(super) accept_other_users: bool,
}

impl Default for FlagPolicyData {
    fn default() -> Self {
        Self {
            case_sensitive: true,
            leet_variation: false,
            accept_other_users: false,
        }
    }
}

#[derive(Clone, Debug, FromRow)]
pub(super) struct StoredFlag {
    pub(super) id: i32,
    pub(super) flag_type: String,
    pub(super) content: String,
    pub(super) data: Value,
    pub(super) revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FlagMatch {
    No,
    Own,
    Other {
        flag_id: i32,
        source_user_id: i32,
        accepted: bool,
        match_tag: [u8; 32],
    },
}

pub(super) fn normalize_definition(
    flag_type: &str,
    content: &str,
    data: Value,
    exposure: &str,
) -> Result<(String, String, Value), ApiError> {
    let flag_type = flag_type.trim().to_ascii_lowercase();
    let content = content.trim();
    if content.is_empty() || content.len() > MAX_FLAG_BYTES || content.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request("Flag content is invalid"));
    }
    if !matches!(flag_type.as_str(), "static" | "regex" | "generated") {
        return Err(ApiError::bad_request("Flag type is invalid"));
    }
    let policy = parse_policy(data)?;
    match flag_type.as_str() {
        "static" => {
            if content.contains(RANDOM_TOKEN_PLACEHOLDER) {
                return Err(ApiError::bad_request(
                    "RANDOM_TOKEN is available only for generated flags",
                ));
            }
            if policy.leet_variation || policy.accept_other_users {
                return Err(ApiError::bad_request(
                    "Static flags do not support per-user options",
                ));
            }
        }
        "regex" => {
            if content.contains(RANDOM_TOKEN_PLACEHOLDER) {
                return Err(ApiError::bad_request(
                    "RANDOM_TOKEN is available only for generated flags",
                ));
            }
            if policy.leet_variation || policy.accept_other_users {
                return Err(ApiError::bad_request(
                    "Regex flags do not support per-user options",
                ));
            }
            compile_regex(content, policy.case_sensitive)?;
        }
        "generated" => {
            if exposure != "private" {
                return Err(ApiError::bad_request(
                    "Generated flags require a private challenge",
                ));
            }
            let placeholders = content.matches(RANDOM_TOKEN_PLACEHOLDER).count();
            if placeholders > 1 {
                return Err(ApiError::bad_request(
                    "A generated flag may contain RANDOM_TOKEN only once",
                ));
            }
            let rendered_bytes = content.len()
                + placeholders * (Uuid::nil().to_string().len() - RANDOM_TOKEN_PLACEHOLDER.len());
            if rendered_bytes > MAX_FLAG_BYTES {
                return Err(ApiError::bad_request(
                    "The rendered generated flag exceeds 512 bytes",
                ));
            }
            let without_supported = content.replace(RANDOM_TOKEN_PLACEHOLDER, "");
            if without_supported.contains("{{") || without_supported.contains("}}") {
                return Err(ApiError::bad_request(
                    "The generated flag contains an unsupported placeholder",
                ));
            }
            let positions = leet_positions(content);
            if policy.leet_variation && positions.is_empty() {
                return Err(ApiError::bad_request(
                    "Leet variation requires at least one replaceable letter",
                ));
            }
            if policy.leet_variation && positions.len() > MAX_LEET_POSITIONS {
                return Err(ApiError::bad_request(
                    "The flag has too many letters for leet variation",
                ));
            }
            if placeholders == 0 && !policy.leet_variation {
                return Err(ApiError::bad_request(
                    "A generated flag requires RANDOM_TOKEN or leet variation",
                ));
            }
        }
        _ => unreachable!(),
    }
    let data = serde_json::to_value(policy)
        .map_err(|_| ApiError::service_unavailable("Flag policy serialization failed"))?;
    Ok((flag_type, content.to_owned(), data))
}

pub(super) fn flag_matches_literal(saved: &str, provided: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        saved == provided
    } else {
        saved.to_lowercase() == provided.to_lowercase()
    }
}

pub(super) fn flag_matches_regex(
    pattern: &str,
    provided: &str,
    case_sensitive: bool,
) -> Result<bool, ApiError> {
    Ok(compile_regex(pattern, case_sensitive)?.is_match(provided))
}

pub(super) async fn generated_flag_match(
    transaction: &mut Transaction<'_, Postgres>,
    flag: &StoredFlag,
    provided: &str,
    submitting_user_id: i32,
    challenge_id: i32,
    secret_key: &str,
) -> Result<FlagMatch, ApiError> {
    let policy = parse_policy(flag.data.clone())?;
    let match_tag = match_tag(secret_key, challenge_id, provided, policy.case_sensitive)?;
    let owner = sqlx::query_as::<_, (i32, i32)>(
        "SELECT flag_id,user_id FROM ctfzone.user_challenge_flags WHERE challenge_id=$1 AND match_tag=$2",
    )
    .bind(challenge_id)
    .bind(match_tag.as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    let Some((matched_flag_id, source_user_id)) = owner else {
        return Ok(FlagMatch::No);
    };
    if matched_flag_id != flag.id {
        return Ok(FlagMatch::No);
    }
    if source_user_id == submitting_user_id {
        Ok(FlagMatch::Own)
    } else {
        Ok(FlagMatch::Other {
            flag_id: flag.id,
            source_user_id,
            accepted: policy.accept_other_users,
            match_tag,
        })
    }
}

pub(super) async fn materialize_for_launch(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: i32,
    user_id: i32,
    secret_key: &str,
) -> Result<Option<String>, ApiError> {
    lock_challenge_definition(transaction, challenge_id).await?;
    let flag = sqlx::query_as::<_, StoredFlag>(
        r#"
        SELECT id,type AS flag_type,content,data,revision
        FROM ctfzone.flags
        WHERE challenge_id=$1 AND type='generated'
        ORDER BY id
        LIMIT 1
        FOR KEY SHARE
        "#,
    )
    .bind(challenge_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    let Some(flag) = flag else {
        return Ok(None);
    };
    materialize_flag(transaction, challenge_id, user_id, &flag, secret_key)
        .await
        .map(Some)
}

pub(super) async fn lock_challenge_definition(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: i32,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1,$2)")
        .bind(CHALLENGE_FLAG_LOCK_NAMESPACE)
        .bind(challenge_id)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    Ok(())
}

async fn materialize_flag(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: i32,
    user_id: i32,
    flag: &StoredFlag,
    secret_key: &str,
) -> Result<String, ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1,$2)")
        .bind(GENERATED_FLAG_LOCK_NAMESPACE)
        .bind(flag.id)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    if let Some((revision, random_token, leet_mask)) =
        sqlx::query_as::<_, (i64, Option<Uuid>, Option<i64>)>(
            "SELECT definition_revision,random_token,leet_mask FROM ctfzone.user_challenge_flags WHERE flag_id=$1 AND user_id=$2",
        )
        .bind(flag.id)
        .bind(user_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(ApiError::database)?
    {
        if revision != flag.revision {
            return Err(ApiError::conflict(
                "The generated flag definition changed after allocation",
            ));
        }
        return Ok(render_generated_flag(
            &flag.content,
            random_token,
            leet_mask.map(|mask| mask as u64),
        ));
    }

    let policy = parse_policy(flag.data.clone())?;
    let has_token = flag.content.contains(RANDOM_TOKEN_PLACEHOLDER);
    let leet_position_count = policy
        .leet_variation
        .then(|| leet_positions(&flag.content).len() as i16);
    let leet_mask = if policy.leet_variation && !has_token {
        Some(next_available_leet_mask(transaction, flag).await?)
    } else if policy.leet_variation {
        let positions = leet_positions(&flag.content).len();
        let maximum = (1_u64 << positions) - 1;
        let random = Uuid::new_v4().as_u128() as u64;
        Some(((random % maximum) + 1) as i64)
    } else {
        None
    };
    let random_token = has_token.then(Uuid::new_v4);
    let rendered = render_generated_flag(
        &flag.content,
        random_token,
        leet_mask.map(|mask| mask as u64),
    );
    let match_tag = match_tag(secret_key, challenge_id, &rendered, policy.case_sensitive)?;
    sqlx::query(
        r#"
        INSERT INTO ctfzone.user_challenge_flags
            (flag_id,challenge_id,user_id,definition_revision,match_tag,random_token,
             leet_mask,leet_position_count)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(flag.id)
    .bind(challenge_id)
    .bind(user_id)
    .bind(flag.revision)
    .bind(match_tag.as_slice())
    .bind(random_token)
    .bind(leet_mask)
    .bind(leet_position_count)
    .execute(&mut **transaction)
    .await
    .map_err(|error| {
        ApiError::conflict_or_database(
            error,
            "A unique flag could not be allocated; review the flag template",
        )
    })?;
    Ok(rendered)
}

async fn next_available_leet_mask(
    transaction: &mut Transaction<'_, Postgres>,
    flag: &StoredFlag,
) -> Result<i64, ApiError> {
    let position_count = leet_positions(&flag.content).len();
    let capacity = ((1_u64 << position_count) - 1) as i64;
    let assigned = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM ctfzone.user_challenge_flags WHERE flag_id=$1",
    )
    .bind(flag.id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    if assigned >= capacity {
        return Err(ApiError::conflict(
            "The leet variation space for this challenge is exhausted",
        ));
    }
    sqlx::query_scalar::<_, i64>(
        r#"
        SELECT candidate
        FROM generate_series(1::bigint,LEAST($2::bigint,$3::bigint)) AS candidate
        LEFT JOIN ctfzone.user_challenge_flags assignment
          ON assignment.flag_id=$1 AND assignment.leet_mask=candidate
        WHERE assignment.flag_id IS NULL
        ORDER BY candidate
        LIMIT 1
        "#,
    )
    .bind(flag.id)
    .bind(capacity)
    .bind(assigned + 1)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)
}

fn render_generated_flag(template: &str, token: Option<Uuid>, mask: Option<u64>) -> String {
    let mut rendered = String::with_capacity(template.len() + 36);
    let mut leet_index = 0_usize;
    let scope = leet_scope(template);
    let mut cursor = 0_usize;
    while cursor < template.len() {
        let remaining = &template[cursor..];
        if remaining.starts_with(RANDOM_TOKEN_PLACEHOLDER) {
            if let Some(token) = token {
                rendered.push_str(&token.to_string());
            } else {
                rendered.push_str(RANDOM_TOKEN_PLACEHOLDER);
            }
            cursor += RANDOM_TOKEN_PLACEHOLDER.len();
            continue;
        }
        let character = remaining
            .chars()
            .next()
            .expect("cursor is before the template end");
        if scope.contains(&cursor) {
            if let Some(replacement) = leet_replacement(character) {
                let replace = mask.is_some_and(|mask| mask & (1_u64 << leet_index) != 0);
                rendered.push(if replace { replacement } else { character });
                leet_index += 1;
            } else {
                rendered.push(character);
            }
        } else {
            rendered.push(character);
        }
        cursor += character.len_utf8();
    }
    rendered
}

fn leet_positions(template: &str) -> Vec<usize> {
    let scope = leet_scope(template);
    template
        .char_indices()
        .filter_map(|(index, character)| {
            (scope.contains(&index)
                && !inside_random_token(template, index)
                && leet_replacement(character).is_some())
            .then_some(index)
        })
        .collect()
}

fn leet_scope(template: &str) -> std::ops::Range<usize> {
    // The random-token marker contains braces of its own. They are syntax for
    // the placeholder, not an outer flag wrapper. Ignore them when deciding
    // whether leet substitutions should be limited to a `{...}` payload.
    let open = template.char_indices().find_map(|(index, character)| {
        (character == '{' && !inside_random_token(template, index)).then_some(index)
    });
    let close = template
        .char_indices()
        .rev()
        .find_map(|(index, character)| {
            (character == '}' && !inside_random_token(template, index)).then_some(index)
        });
    match (open, close) {
        (Some(open), Some(close)) if open < close => open + 1..close,
        _ => 0..template.len(),
    }
}

fn inside_random_token(template: &str, index: usize) -> bool {
    template
        .match_indices(RANDOM_TOKEN_PLACEHOLDER)
        .any(|(start, _)| (start..start + RANDOM_TOKEN_PLACEHOLDER.len()).contains(&index))
}

fn leet_replacement(character: char) -> Option<char> {
    match character {
        'a' | 'A' => Some('4'),
        'e' | 'E' => Some('3'),
        'i' | 'I' => Some('1'),
        'o' | 'O' => Some('0'),
        's' | 'S' => Some('5'),
        't' | 'T' => Some('7'),
        _ => None,
    }
}

fn match_tag(
    secret_key: &str,
    challenge_id: i32,
    flag: &str,
    case_sensitive: bool,
) -> Result<[u8; 32], ApiError> {
    let normalized = if case_sensitive {
        flag.to_owned()
    } else {
        flag.to_lowercase()
    };
    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes())
        .map_err(|_| ApiError::service_unavailable("Flag verification is unavailable"))?;
    mac.update(MATCH_TAG_CONTEXT);
    mac.update(&challenge_id.to_be_bytes());
    mac.update(normalized.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn parse_policy(data: Value) -> Result<FlagPolicyData, ApiError> {
    if data.is_null() {
        return Ok(FlagPolicyData::default());
    }
    serde_json::from_value(data).map_err(|_| ApiError::bad_request("Flag options are invalid"))
}

fn compile_regex(pattern: &str, case_sensitive: bool) -> Result<Regex, ApiError> {
    if pattern.len() > MAX_REGEX_BYTES {
        return Err(ApiError::bad_request("Regex flag is too long"));
    }
    RegexBuilder::new(&format!("^(?:{pattern})$"))
        .case_insensitive(!case_sensitive)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|_| ApiError::bad_request("Regex flag is invalid"))
}

fn empty_object() -> Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_token_is_protected_from_leet_and_replaced_once() {
        let token = Uuid::parse_str("123e4567-e89b-42d3-a456-426614174000").unwrap();
        assert_eq!(
            render_generated_flag("flag{test:{{RANDOM_TOKEN}}}", Some(token), Some(1)),
            "flag{7est:123e4567-e89b-42d3-a456-426614174000}"
        );
        assert_eq!(
            render_generated_flag("flag{test:{{RANDOM_TOKEN}}}", None, Some(1)),
            "flag{7est:{{RANDOM_TOKEN}}}"
        );
        assert_eq!(leet_positions("flag{test}").len(), 4);
    }

    #[test]
    fn leet_scope_preserves_the_flag_prefix() {
        let token = Uuid::parse_str("123e4567-e89b-42d3-a456-426614174000").unwrap();
        assert_eq!(
            render_generated_flag("flag{test}", None, Some(u64::MAX)),
            "flag{7357}"
        );
        assert_eq!(
            render_generated_flag("test-without-braces", None, Some(u64::MAX)),
            "7357-w17h0u7-br4c35"
        );
        assert_eq!(
            render_generated_flag("secret-{{RANDOM_TOKEN}}-test", Some(token), Some(u64::MAX)),
            "53cr37-123e4567-e89b-42d3-a456-426614174000-7357"
        );
        assert_eq!(
            render_generated_flag(
                "flag{secret-{{RANDOM_TOKEN}}-test}",
                Some(token),
                Some(u64::MAX)
            ),
            "flag{53cr37-123e4567-e89b-42d3-a456-426614174000-7357}"
        );
        assert!(
            normalize_definition(
                "generated",
                "secret-{{RANDOM_TOKEN}}-test",
                json!({"leet_variation": true}),
                "private"
            )
            .is_ok()
        );
    }

    #[test]
    fn validates_generated_contract() {
        let data = json!({"leet_variation": true, "accept_other_users": false});
        assert!(normalize_definition("generated", "flag{test}", data, "private").is_ok());
        assert!(normalize_definition("generated", "flag{test}", json!({}), "private").is_err());
        assert!(
            normalize_definition(
                "generated",
                "flag{{RANDOM_TOKEN}}{{RANDOM_TOKEN}}",
                json!({}),
                "private"
            )
            .is_err()
        );

        let uuid_only = format!("flag{{{}:{RANDOM_TOKEN_PLACEHOLDER}}}", "a".repeat(63));
        assert!(
            normalize_definition(
                "generated",
                &uuid_only,
                json!({"leet_variation": false}),
                "private"
            )
            .is_ok()
        );
        assert!(
            normalize_definition(
                "generated",
                &uuid_only,
                json!({"leet_variation": true}),
                "private"
            )
            .is_err()
        );

        let maximum_rendered = format!("flag{{{}:{RANDOM_TOKEN_PLACEHOLDER}}}", "x".repeat(469));
        assert_eq!(maximum_rendered.len(), 492);
        assert!(
            normalize_definition(
                "generated",
                &maximum_rendered,
                json!({"leet_variation": false}),
                "private"
            )
            .is_ok()
        );
        let oversized_rendered = format!("{maximum_rendered}x");
        assert!(
            normalize_definition(
                "generated",
                &oversized_rendered,
                json!({"leet_variation": false}),
                "private"
            )
            .is_err()
        );
    }

    #[test]
    fn regex_is_anchored_and_case_configurable() {
        assert!(flag_matches_regex("flag\\{[0-9]+\\}", "flag{42}", true).unwrap());
        assert!(!flag_matches_regex("flag", "prefix-flag", true).unwrap());
        assert!(flag_matches_regex("FLAG", "flag", false).unwrap());
    }

    #[test]
    fn case_insensitive_match_tag_is_canonical_and_domain_separated() {
        assert_eq!(
            match_tag("secret", 1, "FLAG{YES}", false).unwrap(),
            match_tag("secret", 1, "flag{yes}", false).unwrap()
        );
        assert_ne!(
            match_tag("secret", 1, "FLAG{YES}", true).unwrap(),
            match_tag("secret", 1, "flag{yes}", true).unwrap()
        );
        assert_ne!(
            match_tag("secret", 1, "flag{yes}", true).unwrap(),
            match_tag("secret", 2, "flag{yes}", true).unwrap()
        );
    }
}
