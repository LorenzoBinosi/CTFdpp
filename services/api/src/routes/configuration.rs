use std::collections::HashMap;

use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Postgres, Transaction};

use crate::{
    browser_auth::{normalize_ctf_name, normalize_domain_rules, validate_player_frontend},
    error::ApiError,
};

const SENSITIVE_KEYS: &[&str] = &["registration_code", "mail_password", "mailgun_api_key"];

#[derive(Clone, Debug, sqlx::FromRow)]
pub(super) struct StoredConfig {
    pub(super) id: i32,
    pub(super) key: Option<String>,
    pub(super) value: Option<String>,
}

#[derive(Serialize)]
pub(super) struct PublicConfig {
    id: i32,
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    sensitive: bool,
    configured: bool,
}

impl From<StoredConfig> for PublicConfig {
    fn from(config: StoredConfig) -> Self {
        let sensitive = config.key.as_deref().is_some_and(is_sensitive_key);
        let configured = config
            .value
            .as_deref()
            .is_some_and(|value| !value.is_empty());
        Self {
            id: config.id,
            key: config.key,
            value: (!sensitive).then_some(config.value).flatten(),
            sensitive,
            configured,
        }
    }
}

#[derive(Clone, Copy)]
enum SettingKind {
    String,
    Text,
    Boolean,
    Integer { min: i64, max: i64 },
    DateTime,
    Select(&'static [OptionDefinition]),
    Secret,
}

#[derive(Clone, Copy)]
struct OptionDefinition {
    value: &'static str,
    label: &'static str,
}

#[derive(Clone, Copy)]
struct SettingDefinition {
    section: &'static str,
    key: &'static str,
    label: &'static str,
    help: &'static str,
    kind: SettingKind,
    default: &'static str,
    required: bool,
    read_only: bool,
    warning: Option<&'static str>,
    danger: Option<&'static str>,
    depends_on: Option<(&'static str, &'static [&'static str])>,
}

#[derive(Clone, Copy)]
struct SectionDefinition {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    groups: &'static [GroupDefinition],
}

#[derive(Serialize)]
struct CatalogSection {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    groups: Vec<CatalogGroup>,
    settings: Vec<CatalogSetting>,
}

#[derive(Clone, Copy)]
struct GroupDefinition {
    id: &'static str,
    title: &'static str,
    description: &'static str,
}

#[derive(Clone, Copy, Serialize)]
struct CatalogGroup {
    id: &'static str,
    title: &'static str,
    description: &'static str,
}

impl From<GroupDefinition> for CatalogGroup {
    fn from(group: GroupDefinition) -> Self {
        Self {
            id: group.id,
            title: group.title,
            description: group.description,
        }
    }
}

#[derive(Serialize)]
struct CatalogSetting {
    key: String,
    label: String,
    help: String,
    #[serde(rename = "type")]
    setting_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stored: Option<Value>,
    configured: bool,
    sensitive: bool,
    required: bool,
    read_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    danger: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    options: Vec<CatalogOption>,
    #[serde(skip_serializing_if = "Option::is_none")]
    depends_on: Option<CatalogDependency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<CatalogGroup>,
    advanced: bool,
}

#[derive(Serialize)]
struct CatalogOption {
    value: String,
    label: String,
}

#[derive(Serialize)]
struct CatalogDependency {
    key: String,
    values: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct RegistrationEmail {
    id: i32,
    email: String,
    registered: bool,
}

#[derive(Serialize)]
pub(super) struct ConfigurationCatalog {
    sections: Vec<CatalogSection>,
    registration_emails: Vec<RegistrationEmail>,
    registration_email_count: i64,
    registration_emails_truncated: bool,
}

const USER_MODES: &[OptionDefinition] = &[
    OptionDefinition {
        value: "users",
        label: "Individual users",
    },
    OptionDefinition {
        value: "teams",
        label: "Teams",
    },
];
const VISIBILITY: &[OptionDefinition] = &[
    OptionDefinition {
        value: "public",
        label: "Public",
    },
    OptionDefinition {
        value: "private",
        label: "Authenticated users",
    },
    OptionDefinition {
        value: "admins",
        label: "Administrators",
    },
];
const SCORE_VISIBILITY: &[OptionDefinition] = &[
    OptionDefinition {
        value: "public",
        label: "Public",
    },
    OptionDefinition {
        value: "private",
        label: "Authenticated users",
    },
    OptionDefinition {
        value: "admins",
        label: "Administrators",
    },
    OptionDefinition {
        value: "hidden",
        label: "Hidden",
    },
];
const REGISTRATION_VISIBILITY: &[OptionDefinition] = &[
    OptionDefinition {
        value: "public",
        label: "Public",
    },
    OptionDefinition {
        value: "private",
        label: "Closed",
    },
];
const REGISTRATION_MODES: &[OptionDefinition] = &[
    OptionDefinition {
        value: "open",
        label: "Open registration",
    },
    OptionDefinition {
        value: "domain_rules",
        label: "Email domain rules",
    },
    OptionDefinition {
        value: "access_code",
        label: "Access code",
    },
    OptionDefinition {
        value: "email_allowlist",
        label: "Email allowlist",
    },
];
const ATTEMPT_BEHAVIORS: &[OptionDefinition] = &[
    OptionDefinition {
        value: "lockout",
        label: "Permanent lockout",
    },
    OptionDefinition {
        value: "timeout",
        label: "Temporary timeout",
    },
];
const RATING_MODES: &[OptionDefinition] = &[
    OptionDefinition {
        value: "public",
        label: "Ratings and totals visible",
    },
    OptionDefinition {
        value: "private",
        label: "Ratings allowed, totals hidden",
    },
    OptionDefinition {
        value: "disabled",
        label: "Disabled",
    },
];
const TEAM_DISBANDING: &[OptionDefinition] = &[
    OptionDefinition {
        value: "inactive_only",
        label: "Only before competition activity",
    },
    OptionDefinition {
        value: "disabled",
        label: "Disabled",
    },
];
const MAIL_PROVIDERS: &[OptionDefinition] = &[
    OptionDefinition {
        value: "auto",
        label: "Automatic (legacy)",
    },
    OptionDefinition {
        value: "disabled",
        label: "Disabled",
    },
    OptionDefinition {
        value: "smtp",
        label: "SMTP",
    },
    OptionDefinition {
        value: "mailgun",
        label: "Mailgun",
    },
];

const ACCOUNT_GROUPS: &[GroupDefinition] = &[
    GroupDefinition {
        id: "account_type",
        title: "Account type",
        description: "Choose whether participants compete as individual users or teams.",
    },
    GroupDefinition {
        id: "participant_accounts",
        title: "Participant accounts",
        description: "Common identity, capacity, and account policies for every participant.",
    },
    GroupDefinition {
        id: "team_accounts",
        title: "Team accounts",
        description: "Team creation, membership, capacity, and lifecycle policies.",
    },
    GroupDefinition {
        id: "registration_access",
        title: "Registration access",
        description: "Control whether registration is open and how new participants are admitted.",
    },
];

const ACCOUNT_SETTING_ORDER: &[&str] = &[
    "user_mode",
    "num_users",
    "password_min_length",
    "name_changes",
    "verify_emails",
    "team_creation",
    "team_size",
    "num_teams",
    "team_disbanding",
    "registration_visibility",
    "registration_access_mode",
    "registration_code",
    "domain_whitelist",
    "domain_blacklist",
];

const SECTIONS: &[SectionDefinition] = &[
    SectionDefinition {
        id: "site",
        title: "Site & interface",
        description: "Event identity and the player presentation.",
        groups: &[],
    },
    SectionDefinition {
        id: "visibility",
        title: "Visibility & access",
        description: "Who can register and see challenges, accounts, and scores.",
        groups: &[],
    },
    SectionDefinition {
        id: "schedule",
        title: "Schedule",
        description: "Event timing, scoreboard freeze, and submission availability.",
        groups: &[],
    },
    SectionDefinition {
        id: "accounts",
        title: "Accounts & registration",
        description: "Participant account type, capacity, team policies, and admission.",
        groups: ACCOUNT_GROUPS,
    },
    SectionDefinition {
        id: "challenges",
        title: "Challenges & scoring",
        description: "Submissions, hints, ratings, and participant history.",
        groups: &[],
    },
    SectionDefinition {
        id: "email",
        title: "Email delivery",
        description: "SMTP or Mailgun delivery used for administrator messages.",
        groups: &[],
    },
    SectionDefinition {
        id: "advanced",
        title: "Advanced legacy",
        description: "Preserved legacy configuration not currently interpreted by CTFZone.",
        groups: &[],
    },
];

const SETTINGS: &[SettingDefinition] = &[
    SettingDefinition {
        section: "site",
        key: "ctf_name",
        label: "CTF name",
        help: "Name shown throughout the player and administration interfaces.",
        kind: SettingKind::String,
        default: "CTFZone",
        required: true,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "site",
        key: "ctf_description",
        label: "Description",
        help: "Short event description shown by player frontends.",
        kind: SettingKind::Text,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "site",
        key: "player_frontend",
        label: "Player frontend",
        help: "Installed player frontend identifier. The Python presentation service validates that it is installed.",
        kind: SettingKind::String,
        default: "terminal",
        required: true,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "accounts",
        key: "user_mode",
        label: "Competition mode",
        help: "Score and solve participants as individual users or as teams.",
        kind: SettingKind::Select(USER_MODES),
        default: "users",
        required: true,
        read_only: false,
        warning: Some(
            "Changing competition mode after participants or competition activity exist is blocked.",
        ),
        danger: Some("This changes score ownership and participant workflows."),
        depends_on: None,
    },
    SettingDefinition {
        section: "schedule",
        key: "start",
        label: "Start time",
        help: "Unix timestamp at which non-admin participants may access challenges; leave empty for immediate access.",
        kind: SettingKind::DateTime,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "schedule",
        key: "end",
        label: "End time",
        help: "Unix timestamp at which challenge access ends; leave empty for no end time.",
        kind: SettingKind::DateTime,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "schedule",
        key: "freeze",
        label: "Scoreboard freeze",
        help: "Unix timestamp after which score changes are hidden; leave empty to disable freezing.",
        kind: SettingKind::DateTime,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "schedule",
        key: "paused",
        label: "Pause submissions",
        help: "Reject participant flag submissions while leaving the portal available.",
        kind: SettingKind::Boolean,
        default: "false",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "schedule",
        key: "view_after_ctf",
        label: "View challenges after event",
        help: "Allow participants to view challenges after the end time. Submissions remain time-gated.",
        kind: SettingKind::Boolean,
        default: "false",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "visibility",
        key: "score_visibility",
        label: "Score visibility",
        help: "Who may view scores and the scoreboard.",
        kind: SettingKind::Select(SCORE_VISIBILITY),
        default: "public",
        required: true,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "visibility",
        key: "account_visibility",
        label: "Account visibility",
        help: "Who may view participant profiles and account data.",
        kind: SettingKind::Select(VISIBILITY),
        default: "public",
        required: true,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "accounts",
        key: "registration_visibility",
        label: "Registration status",
        help: "Open or close the public registration route. The admission policy below is applied only while registration is open.",
        kind: SettingKind::Select(REGISTRATION_VISIBILITY),
        default: "public",
        required: true,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "accounts",
        key: "registration_access_mode",
        label: "Admission policy",
        help: "Choose exactly one registration policy. Settings for inactive policies remain stored but are not enforced.",
        kind: SettingKind::Select(REGISTRATION_MODES),
        default: "open",
        required: true,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "accounts",
        key: "registration_code",
        label: "Registration code",
        help: "Secret code required when registration access uses an access code.",
        kind: SettingKind::Secret,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: Some(("registration_access_mode", &["access_code"])),
    },
    SettingDefinition {
        section: "accounts",
        key: "domain_whitelist",
        label: "Allowed email domains",
        help: "Comma-separated exact domains or wildcard suffixes such as *.example.org. Empty allows every domain not denied below.",
        kind: SettingKind::Text,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: Some(("registration_access_mode", &["domain_rules"])),
    },
    SettingDefinition {
        section: "accounts",
        key: "domain_blacklist",
        label: "Denied email domains",
        help: "Comma-separated exact domains or wildcard suffixes denied during registration.",
        kind: SettingKind::Text,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: Some(("registration_access_mode", &["domain_rules"])),
    },
    SettingDefinition {
        section: "accounts",
        key: "num_users",
        label: "Participant limit",
        help: "Maximum active visible users; 0 means unlimited. Email allowlist mode intentionally bypasses this limit.",
        kind: SettingKind::Integer {
            min: 0,
            max: 10_000_000,
        },
        default: "0",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "accounts",
        key: "password_min_length",
        label: "Minimum password length",
        help: "Minimum participant password length for registration and self-service password changes.",
        kind: SettingKind::Integer { min: 0, max: 128 },
        default: "0",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "accounts",
        key: "name_changes",
        label: "Allow name changes",
        help: "Allow participants to change their own display name.",
        kind: SettingKind::Boolean,
        default: "true",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "accounts",
        key: "team_creation",
        label: "Allow participant team creation",
        help: "Allow participants without a team to create one. Joining an existing team by invite remains available.",
        kind: SettingKind::Boolean,
        default: "true",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: Some(("user_mode", &["teams"])),
    },
    SettingDefinition {
        section: "accounts",
        key: "team_size",
        label: "Maximum team size",
        help: "Maximum participants per team; 0 means unlimited. Lowering this does not remove existing members.",
        kind: SettingKind::Integer {
            min: 0,
            max: 10_000_000,
        },
        default: "0",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: Some(("user_mode", &["teams"])),
    },
    SettingDefinition {
        section: "accounts",
        key: "num_teams",
        label: "Maximum number of teams",
        help: "Maximum active visible teams participants may create; 0 means unlimited. Existing teams are not removed, and administrators can still manage teams.",
        kind: SettingKind::Integer {
            min: 0,
            max: 10_000_000,
        },
        default: "0",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: Some(("user_mode", &["teams"])),
    },
    SettingDefinition {
        section: "accounts",
        key: "team_disbanding",
        label: "Allow team disbanding",
        help: "Allow team captains to disband teams that have no competition activity.",
        kind: SettingKind::Select(TEAM_DISBANDING),
        default: "inactive_only",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: Some(("user_mode", &["teams"])),
    },
    SettingDefinition {
        section: "accounts",
        key: "verify_emails",
        label: "Require verified email",
        help: "Require email verification before challenge access.",
        kind: SettingKind::Boolean,
        default: "false",
        required: false,
        read_only: false,
        warning: Some(
            "When enabled, unverified participants cannot access challenges. Each user requests and completes verification from their own profile.",
        ),
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "visibility",
        key: "challenge_visibility",
        label: "Challenge visibility",
        help: "Who may view challenges.",
        kind: SettingKind::Select(VISIBILITY),
        default: "private",
        required: true,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "challenges",
        key: "incorrect_submissions_per_min",
        label: "Incorrect submissions per minute",
        help: "Global per-participant incorrect-submission limit.",
        kind: SettingKind::Integer {
            min: 1,
            max: 10_000,
        },
        default: "10",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "challenges",
        key: "max_attempts_behavior",
        label: "Maximum-attempt behavior",
        help: "Whether a challenge attempt limit locks permanently or resets after a timeout.",
        kind: SettingKind::Select(ATTEMPT_BEHAVIORS),
        default: "lockout",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "challenges",
        key: "max_attempts_timeout",
        label: "Attempt timeout",
        help: "Seconds before failed attempts expire when timeout behavior is selected.",
        kind: SettingKind::Integer {
            min: 1,
            max: 31_536_000,
        },
        default: "300",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: Some(("max_attempts_behavior", &["timeout"])),
    },
    SettingDefinition {
        section: "challenges",
        key: "challenge_ratings",
        label: "Challenge ratings",
        help: "Allow challenge ratings and control whether aggregate ratings are public.",
        kind: SettingKind::Select(RATING_MODES),
        default: "public",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "challenges",
        key: "hints_free_public_access",
        label: "Free hints for guests",
        help: "Allow unauthenticated visitors to read zero-cost hints.",
        kind: SettingKind::Boolean,
        default: "false",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "challenges",
        key: "view_self_submissions",
        label: "View own submissions",
        help: "Allow participants to inspect their own submission history.",
        kind: SettingKind::Boolean,
        default: "false",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "email",
        key: "mail_provider",
        label: "Email provider",
        help: "Select the delivery provider. Automatic uses a complete Mailgun configuration first, then SMTP. Disabled never sends email.",
        kind: SettingKind::Select(MAIL_PROVIDERS),
        default: "auto",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "email",
        key: "mail_server",
        label: "SMTP server",
        help: "SMTP server hostname. Used when Mailgun is not fully configured.",
        kind: SettingKind::String,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "email",
        key: "mail_port",
        label: "SMTP port",
        help: "SMTP server port.",
        kind: SettingKind::Integer {
            min: 1,
            max: 65_535,
        },
        default: "587",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "email",
        key: "mail_username",
        label: "SMTP username",
        help: "Optional SMTP authentication username.",
        kind: SettingKind::String,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "email",
        key: "mail_password",
        label: "SMTP password",
        help: "Optional SMTP authentication password. Existing values are never returned.",
        kind: SettingKind::Secret,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "email",
        key: "mail_ssl",
        label: "Implicit TLS",
        help: "Connect using implicit SMTP TLS. Cannot be enabled with STARTTLS.",
        kind: SettingKind::Boolean,
        default: "false",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "email",
        key: "mail_tls",
        label: "STARTTLS",
        help: "Upgrade the SMTP connection with STARTTLS. Cannot be enabled with implicit TLS.",
        kind: SettingKind::Boolean,
        default: "false",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "email",
        key: "mailfrom_addr",
        label: "Sender address",
        help: "From address for administrator email messages.",
        kind: SettingKind::String,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "email",
        key: "user_creation_email_subject",
        label: "Email subject",
        help: "Message subject; {ctf_name} is replaced with the configured event name.",
        kind: SettingKind::String,
        default: "Message from {ctf_name}",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "email",
        key: "mailgun_base_url",
        label: "Mailgun API base URL",
        help: "Mailgun messages endpoint base URL. Mailgun is used only when this and its API key are both configured.",
        kind: SettingKind::String,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
    SettingDefinition {
        section: "email",
        key: "mailgun_api_key",
        label: "Mailgun API key",
        help: "Mailgun API credential. Existing values are never returned.",
        kind: SettingKind::Secret,
        default: "",
        required: false,
        read_only: false,
        warning: None,
        danger: None,
        depends_on: None,
    },
];

pub(super) fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    SENSITIVE_KEYS.contains(&key.as_str())
        || key.ends_with("_password")
        || key.ends_with("_secret")
        || key.ends_with("_token")
        || key.ends_with("_api_key")
}

fn setting(key: &str) -> Option<&'static SettingDefinition> {
    SETTINGS.iter().find(|definition| definition.key == key)
}

pub(super) async fn catalog(database: &PgPool) -> Result<ConfigurationCatalog, ApiError> {
    let stored_rows = sqlx::query_as::<_, StoredConfig>(
        "SELECT id,key,value FROM ctfzone.config ORDER BY key,id",
    )
    .fetch_all(database)
    .await
    .map_err(ApiError::database)?;
    let mut stored = HashMap::new();
    for row in stored_rows {
        if let Some(key) = row.key {
            stored.insert(key, (row.id, row.value));
        }
    }

    let inferred_registration_mode = if stored
        .get("registration_access_mode")
        .and_then(|(_, value)| value.as_deref())
        .is_none_or(|value| value.is_empty())
    {
        if stored
            .get("registration_code")
            .and_then(|(_, value)| value.as_deref())
            .is_some_and(|value| !value.is_empty())
        {
            Some("access_code".to_owned())
        } else if ["domain_whitelist", "domain_blacklist"].iter().any(|key| {
            stored
                .get(*key)
                .and_then(|(_, value)| value.as_deref())
                .is_some_and(|value| !value.is_empty())
        }) {
            Some("domain_rules".to_owned())
        } else {
            None
        }
    } else {
        None
    };

    let mut sections = SECTIONS
        .iter()
        .map(|section| CatalogSection {
            id: section.id,
            title: section.title,
            description: section.description,
            groups: section
                .groups
                .iter()
                .copied()
                .map(CatalogGroup::from)
                .collect(),
            settings: Vec::new(),
        })
        .collect::<Vec<_>>();
    for definition in SETTINGS {
        let stored_value = stored.remove(definition.key).and_then(|(_, value)| value);
        let mut catalog_setting = known_catalog_setting(definition, stored_value);
        if definition.key == "registration_access_mode" {
            if let Some(inferred) = inferred_registration_mode.as_ref() {
                catalog_setting.value = Some(Value::String(inferred.clone()));
                catalog_setting.effective = Some(Value::String(inferred.clone()));
            }
        }
        sections
            .iter_mut()
            .find(|section| section.id == definition.section)
            .expect("every setting section is declared")
            .settings
            .push(catalog_setting);
    }
    if let Some(accounts) = sections.iter_mut().find(|section| section.id == "accounts") {
        accounts.settings.sort_by_key(|setting| {
            ACCOUNT_SETTING_ORDER
                .iter()
                .position(|key| *key == setting.key)
                .unwrap_or(usize::MAX)
        });
    }
    let advanced = sections
        .iter_mut()
        .find(|section| section.id == "advanced")
        .expect("advanced section is declared");
    if let Some((_, stored_value)) = stored.remove("social_shares") {
        let mut legacy = legacy_catalog_setting("social_shares".to_owned(), stored_value);
        legacy.read_only = true;
        legacy.warning = Some(
            "Stored for compatibility, but player share pages are not implemented yet.".to_owned(),
        );
        advanced.settings.push(legacy);
    }
    let mut legacy = stored.into_iter().collect::<Vec<_>>();
    legacy.sort_by(|left, right| left.0.cmp(&right.0));
    for (key, (_, stored_value)) in legacy {
        if key == crate::setup::COMPLETED_MARKER_KEY || key == "private_challenges" {
            continue;
        }
        advanced
            .settings
            .push(legacy_catalog_setting(key, stored_value));
    }
    sections.retain(|section| !section.settings.is_empty());

    let registration_email_total =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ctfzone.registration_email_allowlist")
            .fetch_one(database)
            .await
            .map_err(ApiError::database)?;
    let registration_emails = sqlx::query_as::<_, (i32, String, bool)>(
        r#"
        SELECT a.id,a.email,EXISTS(SELECT 1 FROM ctfzone.users u WHERE lower(u.email)=lower(a.email))
        FROM ctfzone.registration_email_allowlist a ORDER BY a.email LIMIT 200
        "#,
    )
    .fetch_all(database)
    .await
    .map_err(ApiError::database)?
    .into_iter()
    .map(|(id, email, registered)| RegistrationEmail { id, email, registered })
    .collect();
    Ok(ConfigurationCatalog {
        sections,
        registration_emails,
        registration_email_count: registration_email_total,
        registration_emails_truncated: registration_email_total > 200,
    })
}

fn known_catalog_setting(
    definition: &SettingDefinition,
    stored_value: Option<String>,
) -> CatalogSetting {
    let sensitive =
        matches!(definition.kind, SettingKind::Secret) || is_sensitive_key(definition.key);
    let configured = stored_value
        .as_deref()
        .is_some_and(|value| !value.is_empty());
    let parsed_stored = stored_value
        .as_deref()
        .and_then(|value| parse_stored_value(definition.kind, value));
    let parsed_default = parse_stored_value(definition.kind, definition.default);
    let effective = parsed_stored.clone().or_else(|| parsed_default.clone());
    let read_only = definition.read_only;
    let visible = |value: Option<Value>| (!sensitive).then_some(value).flatten();
    CatalogSetting {
        key: definition.key.to_owned(),
        label: definition.label.to_owned(),
        help: definition.help.to_owned(),
        setting_type: setting_type(definition.kind),
        value: visible(effective.clone()),
        default: visible(parsed_default),
        effective: visible(effective),
        stored: visible(parsed_stored),
        configured,
        sensitive,
        required: definition.required,
        read_only,
        warning: definition.warning.map(str::to_owned),
        danger: definition.danger.map(str::to_owned),
        options: options(definition.kind),
        depends_on: definition
            .depends_on
            .map(|(key, values)| CatalogDependency {
                key: key.to_owned(),
                values: values.iter().map(|value| (*value).to_owned()).collect(),
            }),
        group: account_group(definition.key).map(CatalogGroup::from),
        advanced: false,
    }
}

fn legacy_catalog_setting(key: String, stored_value: Option<String>) -> CatalogSetting {
    let sensitive = is_sensitive_key(&key);
    let configured = stored_value
        .as_deref()
        .is_some_and(|value| !value.is_empty());
    let visible = (!sensitive).then(|| Value::String(stored_value.clone().unwrap_or_default()));
    CatalogSetting {
        label: key.clone(),
        help: "Preserved legacy setting. CTFZone does not currently interpret this value."
            .to_owned(),
        setting_type: if sensitive { "secret" } else { "string" },
        key,
        value: visible.clone(),
        default: None,
        effective: visible.clone(),
        stored: visible,
        configured,
        sensitive,
        required: false,
        read_only: false,
        warning: Some("Advanced legacy setting; changing it may have no effect.".to_owned()),
        danger: None,
        options: Vec::new(),
        depends_on: None,
        group: None,
        advanced: true,
    }
}

fn account_group(key: &str) -> Option<GroupDefinition> {
    let id = match key {
        "user_mode" => "account_type",
        "num_users" | "password_min_length" | "name_changes" | "verify_emails" => {
            "participant_accounts"
        }
        "team_creation" | "team_size" | "num_teams" | "team_disbanding" => "team_accounts",
        "registration_visibility"
        | "registration_access_mode"
        | "registration_code"
        | "domain_whitelist"
        | "domain_blacklist" => "registration_access",
        _ => return None,
    };
    ACCOUNT_GROUPS.iter().find(|group| group.id == id).copied()
}

fn setting_type(kind: SettingKind) -> &'static str {
    match kind {
        SettingKind::String => "string",
        SettingKind::Text => "text",
        SettingKind::Boolean => "boolean",
        SettingKind::Integer { .. } => "integer",
        SettingKind::DateTime => "datetime",
        SettingKind::Select(_) => "select",
        SettingKind::Secret => "secret",
    }
}

fn options(kind: SettingKind) -> Vec<CatalogOption> {
    match kind {
        SettingKind::Select(options) => options
            .iter()
            .map(|option| CatalogOption {
                value: option.value.to_owned(),
                label: option.label.to_owned(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_stored_value(kind: SettingKind, value: &str) -> Option<Value> {
    if value.is_empty() && matches!(kind, SettingKind::DateTime | SettingKind::Integer { .. }) {
        return None;
    }
    match kind {
        SettingKind::Boolean => parse_bool_text(value).map(Value::Bool),
        SettingKind::Integer { .. } | SettingKind::DateTime => {
            value.parse::<i64>().ok().map(|value| json!(value))
        }
        _ => Some(Value::String(value.to_owned())),
    }
}

pub(super) async fn normalize_mutations(
    transaction: &mut Transaction<'_, Postgres>,
    request: &Map<String, Value>,
) -> Result<Vec<(String, String)>, ApiError> {
    let mut proposed = request.clone();
    proposed.remove("clear_registration_access_modes");
    if proposed.contains_key("private_challenges") {
        return Err(ApiError::bad_request(
            "Private challenge runtime settings use the controller settings endpoint",
        ));
    }
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(0x4354_465A_i64)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    let current_rows = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT key,value FROM ctfzone.config ORDER BY id",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    let mut merged = current_rows
        .into_iter()
        .filter_map(|(key, value)| key.map(|key| (key, value.unwrap_or_default())))
        .collect::<HashMap<_, _>>();
    let mut normalized = Vec::with_capacity(proposed.len());
    for (key, value) in proposed {
        let value = normalize_value(&key, value, merged.get(&key).map(String::as_str))?;
        merged.insert(key.clone(), value.clone());
        normalized.push((key, value));
    }
    validate_cross_fields(&merged)?;
    validate_user_mode_transition(transaction, &merged, &normalized).await?;
    Ok(normalized)
}

fn normalize_value(key: &str, value: Value, current: Option<&str>) -> Result<String, ApiError> {
    validate_key(key)?;
    if key == crate::setup::COMPLETED_MARKER_KEY {
        return Err(ApiError::bad_request(
            "The setup completion marker cannot be changed through configuration",
        ));
    }
    if key == "social_shares" {
        return Err(ApiError::bad_request(
            "Social sharing cannot be enabled until player share pages are implemented",
        ));
    }
    let Some(definition) = setting(key) else {
        return generic_value(value);
    };
    if definition.read_only {
        return Err(ApiError::bad_request(format!(
            "{} is read-only",
            definition.label
        )));
    }
    match definition.kind {
        SettingKind::String | SettingKind::Text => {
            let value = text_value(value, definition.label)?;
            if value.contains('\0')
                || (value.chars().any(char::is_control) && definition.kind_is_string())
            {
                return Err(ApiError::bad_request(format!(
                    "{} contains control characters",
                    definition.label
                )));
            }
            if value.len() > 100_000 {
                return Err(ApiError::bad_request(format!(
                    "{} is too long",
                    definition.label
                )));
            }
            match key {
                "ctf_name" => normalize_ctf_name(&value),
                "domain_whitelist" | "domain_blacklist" => normalize_domain_rules(&value),
                "player_frontend" => {
                    validate_player_frontend(&value)?;
                    Ok(value)
                }
                "mailgun_base_url" if !value.is_empty() => {
                    let url = reqwest::Url::parse(&value)
                        .map_err(|_| ApiError::bad_request("Mailgun API base URL is invalid"))?;
                    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                        return Err(ApiError::bad_request(
                            "Mailgun API base URL must use HTTP or HTTPS and include a host",
                        ));
                    }
                    Ok(value)
                }
                "mail_server"
                    if !value.is_empty()
                        && (value.len() > 255 || value.chars().any(char::is_whitespace)) =>
                {
                    Err(ApiError::bad_request("SMTP server name is invalid"))
                }
                "mailfrom_addr"
                    if !value.is_empty() && value.parse::<lettre::message::Mailbox>().is_err() =>
                {
                    Err(ApiError::bad_request("Email sender address is invalid"))
                }
                "mail_port" => unreachable!(),
                _ => Ok(value),
            }
        }
        SettingKind::Secret => match value {
            Value::Null => Ok(String::new()),
            Value::String(value) if value.is_empty() => Ok(current.unwrap_or_default().to_owned()),
            Value::String(value)
                if value.len() <= 10_000 && !value.chars().any(char::is_control) =>
            {
                Ok(value)
            }
            Value::String(_) => Err(ApiError::bad_request(format!(
                "{} is invalid",
                definition.label
            ))),
            _ => Err(ApiError::bad_request(format!(
                "{} must be text or null",
                definition.label
            ))),
        },
        SettingKind::Boolean => Ok(parse_bool(&value)?.to_string()),
        SettingKind::Integer { min, max } => {
            let integer = parse_integer(&value, false)?.ok_or_else(|| {
                ApiError::bad_request(format!("{} must be an integer", definition.label))
            })?;
            if !(min..=max).contains(&integer) {
                return Err(ApiError::bad_request(format!(
                    "{} must be between {min} and {max}",
                    definition.label
                )));
            }
            Ok(integer.to_string())
        }
        SettingKind::DateTime => {
            let timestamp = parse_integer(&value, true)?;
            if timestamp.is_some_and(|timestamp| !(0..=253_402_300_799).contains(&timestamp)) {
                return Err(ApiError::bad_request(format!(
                    "{} must be a Unix timestamp between 0 and year 9999",
                    definition.label
                )));
            }
            Ok(timestamp.map_or_else(String::new, |value| value.to_string()))
        }
        SettingKind::Select(options) => {
            let value = text_value(value, definition.label)?;
            if !options.iter().any(|option| option.value == value) {
                return Err(ApiError::bad_request(format!(
                    "{} has an unsupported value",
                    definition.label
                )));
            }
            Ok(value)
        }
    }
}

impl SettingDefinition {
    fn kind_is_string(&self) -> bool {
        matches!(self.kind, SettingKind::String)
    }
}

fn validate_cross_fields(values: &HashMap<String, String>) -> Result<(), ApiError> {
    let integer = |key: &str| {
        values
            .get(key)
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse::<i64>().ok())
    };
    let start = integer("start");
    let end = integer("end");
    let freeze = integer("freeze");
    if start.zip(end).is_some_and(|(start, end)| start >= end) {
        return Err(ApiError::bad_request(
            "Event end time must be after its start time",
        ));
    }
    if let Some(freeze) = freeze {
        if start.is_some_and(|start| freeze < start) || end.is_some_and(|end| freeze > end) {
            return Err(ApiError::bad_request(
                "Scoreboard freeze must be within the configured event window",
            ));
        }
    }
    let enabled = |key: &str| {
        values
            .get(key)
            .and_then(|value| parse_bool_text(value))
            .unwrap_or(false)
    };
    if enabled("mail_ssl") && enabled("mail_tls") {
        return Err(ApiError::bad_request(
            "Email cannot enable both implicit TLS and STARTTLS",
        ));
    }
    if values.get("registration_access_mode").map(String::as_str) == Some("access_code")
        && values
            .get("registration_code")
            .is_none_or(|value| value.is_empty())
    {
        return Err(ApiError::bad_request(
            "Registration code is required for access-code registration",
        ));
    }
    if enabled("verify_emails") {
        if values
            .get("mailfrom_addr")
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(ApiError::bad_request(
                "Email sender is required when email verification is enabled",
            ));
        }
        let mailgun_ready = values
            .get("mailgun_base_url")
            .is_some_and(|value| !value.trim().is_empty())
            && values
                .get("mailgun_api_key")
                .is_some_and(|value| !value.trim().is_empty());
        let smtp_ready = values
            .get("mail_server")
            .is_some_and(|value| !value.trim().is_empty());
        let provider_ready = match values.get("mail_provider").map(String::as_str) {
            Some("smtp") => smtp_ready,
            Some("mailgun") => mailgun_ready,
            None | Some("auto") => mailgun_ready || smtp_ready,
            _ => false,
        };
        if !provider_ready {
            return Err(ApiError::bad_request(
                "A working SMTP or Mailgun configuration is required when email verification is enabled",
            ));
        }
    }
    match values.get("mail_provider").map(String::as_str) {
        Some("smtp")
            if values
                .get("mail_server")
                .is_none_or(|value| value.trim().is_empty()) =>
        {
            return Err(ApiError::bad_request(
                "SMTP server is required when SMTP is selected",
            ));
        }
        Some("mailgun")
            if values
                .get("mailgun_base_url")
                .is_none_or(|value| value.trim().is_empty())
                || values
                    .get("mailgun_api_key")
                    .is_none_or(|value| value.trim().is_empty()) =>
        {
            return Err(ApiError::bad_request(
                "Mailgun base URL and API key are required when Mailgun is selected",
            ));
        }
        _ => {}
    }
    Ok(())
}

async fn validate_user_mode_transition(
    transaction: &mut Transaction<'_, Postgres>,
    merged: &HashMap<String, String>,
    normalized: &[(String, String)],
) -> Result<(), ApiError> {
    if !normalized.iter().any(|(key, _)| key == "user_mode") {
        return Ok(());
    }
    let previous = sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM ctfzone.config WHERE key='user_mode'",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .flatten()
    .unwrap_or_else(|| "users".to_owned());
    let requested = merged
        .get("user_mode")
        .map(String::as_str)
        .unwrap_or("users");
    if previous == requested {
        return Ok(());
    }
    sqlx::query(
        "LOCK TABLE ctfzone.users,ctfzone.teams,ctfzone.submissions,ctfzone.solves,ctfzone.awards IN SHARE MODE",
    )
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    let has_activity = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(SELECT 1 FROM ctfzone.users WHERE type <> 'admin')
            OR EXISTS(SELECT 1 FROM ctfzone.teams)
            OR EXISTS(SELECT 1 FROM ctfzone.submissions)
            OR EXISTS(SELECT 1 FROM ctfzone.solves)
            OR EXISTS(SELECT 1 FROM ctfzone.awards)
        "#,
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    if has_activity {
        return Err(ApiError::conflict(
            "Competition mode cannot change after participants or competition activity exist",
        ));
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), ApiError> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(ApiError::bad_request("Configuration key is invalid"));
    }
    Ok(())
}

fn generic_value(value: Value) -> Result<String, ApiError> {
    match value {
        Value::String(value) => Ok(value),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Null => Ok(String::new()),
        _ => serde_json::to_string(&value)
            .map_err(|_| ApiError::bad_request("Configuration value is invalid")),
    }
}

fn text_value(value: Value, label: &str) -> Result<String, ApiError> {
    value
        .as_str()
        .map(str::trim)
        .map(str::to_owned)
        .ok_or_else(|| ApiError::bad_request(format!("{label} must be text")))
}

fn parse_bool(value: &Value) -> Result<bool, ApiError> {
    match value {
        Value::Bool(value) => Ok(*value),
        Value::String(value) => {
            parse_bool_text(value).ok_or_else(|| ApiError::bad_request("Setting must be a boolean"))
        }
        _ => Err(ApiError::bad_request("Setting must be a boolean")),
    }
}

fn parse_bool_text(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_integer(value: &Value, nullable: bool) -> Result<Option<i64>, ApiError> {
    match value {
        Value::Null if nullable => Ok(None),
        Value::String(value) if nullable && value.trim().is_empty() => Ok(None),
        Value::String(value) => value
            .trim()
            .parse::<i64>()
            .map(Some)
            .map_err(|_| ApiError::bad_request("Setting must be an integer")),
        Value::Number(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| ApiError::bad_request("Setting must be an integer")),
        _ => Err(ApiError::bad_request("Setting must be an integer")),
    }
}

pub(super) async fn upsert_normalized(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    value: String,
) -> Result<StoredConfig, ApiError> {
    sqlx::query_as::<_, StoredConfig>(
        r#"
        INSERT INTO ctfzone.config (key,value) VALUES ($1,$2)
        ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value
        RETURNING id,key,value
        "#,
    )
    .bind(key)
    .bind(value)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)
}

pub(super) async fn delete_legacy(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<u64, ApiError> {
    validate_key(key)?;
    if setting(key).is_some() || key == crate::setup::COMPLETED_MARKER_KEY {
        return Err(ApiError::bad_request(
            "Known configuration settings must be changed to their default value instead of deleted",
        ));
    }
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(0x4354_465A_i64)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    sqlx::query("DELETE FROM ctfzone.config WHERE key=$1")
        .bind(key)
        .execute(&mut **transaction)
        .await
        .map(|result| result.rows_affected())
        .map_err(ApiError::database)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn sensitive_values_never_serialize() {
        let sentinel = "do-not-leak".to_owned();
        for key in [
            "registration_code",
            "mail_password",
            "mailgun_api_key",
            "legacy_token",
            "SMTP_PASSWORD",
            "CUSTOM_TOKEN",
            "MAILGUN_API_KEY",
        ] {
            let public = PublicConfig::from(StoredConfig {
                id: 1,
                key: Some(key.to_owned()),
                value: Some(sentinel.clone()),
            });
            let serialized = serde_json::to_string(&public).unwrap();
            assert!(!serialized.contains(&sentinel));
            assert!(serialized.contains("\"configured\":true"));
        }
        let catalog = legacy_catalog_setting("custom_secret".to_owned(), Some(sentinel.clone()));
        assert!(!serde_json::to_string(&catalog).unwrap().contains(&sentinel));
    }

    #[test]
    fn catalog_covers_every_known_runtime_setting() {
        let keys = SETTINGS
            .iter()
            .map(|setting| setting.key)
            .collect::<HashSet<_>>();
        for key in [
            "ctf_name",
            "ctf_description",
            "player_frontend",
            "user_mode",
            "start",
            "end",
            "freeze",
            "paused",
            "view_after_ctf",
            "score_visibility",
            "account_visibility",
            "registration_visibility",
            "registration_access_mode",
            "registration_code",
            "domain_whitelist",
            "domain_blacklist",
            "num_users",
            "password_min_length",
            "name_changes",
            "team_creation",
            "team_size",
            "num_teams",
            "team_disbanding",
            "verify_emails",
            "challenge_visibility",
            "incorrect_submissions_per_min",
            "max_attempts_behavior",
            "max_attempts_timeout",
            "challenge_ratings",
            "hints_free_public_access",
            "view_self_submissions",
            "mail_provider",
            "mail_server",
            "mail_port",
            "mail_username",
            "mail_password",
            "mail_ssl",
            "mail_tls",
            "mailfrom_addr",
            "user_creation_email_subject",
            "mailgun_base_url",
            "mailgun_api_key",
        ] {
            assert!(keys.contains(key), "missing catalog definition for {key}");
        }
    }

    #[test]
    fn catalog_sections_and_keys_are_unique_and_complete() {
        let section_ids = SECTIONS
            .iter()
            .map(|section| section.id)
            .collect::<HashSet<_>>();
        assert_eq!(section_ids.len(), SECTIONS.len());
        let keys = SETTINGS
            .iter()
            .map(|setting| setting.key)
            .collect::<HashSet<_>>();
        assert_eq!(keys.len(), SETTINGS.len());
        for definition in SETTINGS {
            assert!(
                section_ids.contains(definition.section),
                "unknown section {} for {}",
                definition.section,
                definition.key
            );
        }
    }

    #[test]
    fn account_and_registration_settings_share_one_ordered_grouped_section() {
        let section_ids = SECTIONS
            .iter()
            .map(|section| section.id)
            .collect::<Vec<_>>();
        assert!(section_ids.contains(&"accounts"));
        assert!(!section_ids.contains(&"registration"));
        assert_eq!(
            SECTIONS
                .iter()
                .find(|section| section.id == "accounts")
                .unwrap()
                .title,
            "Accounts & registration"
        );

        assert_eq!(
            ACCOUNT_SETTING_ORDER,
            [
                "user_mode",
                "num_users",
                "password_min_length",
                "name_changes",
                "verify_emails",
                "team_creation",
                "team_size",
                "num_teams",
                "team_disbanding",
                "registration_visibility",
                "registration_access_mode",
                "registration_code",
                "domain_whitelist",
                "domain_blacklist",
            ]
        );
        for key in ACCOUNT_SETTING_ORDER {
            let definition = setting(key).unwrap_or_else(|| panic!("missing definition for {key}"));
            assert_eq!(definition.section, "accounts");
            assert!(account_group(key).is_some(), "missing group for {key}");
        }
        assert_eq!(
            ACCOUNT_GROUPS
                .iter()
                .map(|group| group.id)
                .collect::<Vec<_>>(),
            vec![
                "account_type",
                "participant_accounts",
                "team_accounts",
                "registration_access",
            ]
        );
        for (group, expected) in [
            ("account_type", vec!["user_mode"]),
            (
                "participant_accounts",
                vec![
                    "num_users",
                    "password_min_length",
                    "name_changes",
                    "verify_emails",
                ],
            ),
            (
                "team_accounts",
                vec!["team_creation", "team_size", "num_teams", "team_disbanding"],
            ),
            (
                "registration_access",
                vec![
                    "registration_visibility",
                    "registration_access_mode",
                    "registration_code",
                    "domain_whitelist",
                    "domain_blacklist",
                ],
            ),
        ] {
            assert_eq!(
                ACCOUNT_SETTING_ORDER
                    .iter()
                    .copied()
                    .filter(|key| account_group(key).is_some_and(|value| value.id == group))
                    .collect::<Vec<_>>(),
                expected
            );
        }
        for key in ["team_creation", "team_size", "num_teams", "team_disbanding"] {
            assert_eq!(
                setting(key).unwrap().depends_on,
                Some(("user_mode", &["teams"][..]))
            );
        }
    }

    #[test]
    fn validates_types_ranges_enums_and_cross_fields() {
        assert_eq!(
            normalize_value("paused", json!(true), None).unwrap(),
            "true"
        );
        assert!(normalize_value("paused", json!("perhaps"), None).is_err());
        assert_eq!(
            normalize_value("mail_port", json!(587), None).unwrap(),
            "587"
        );
        assert!(normalize_value("mail_port", json!(70_000), None).is_err());
        assert!(normalize_value("score_visibility", json!("world"), None).is_err());
        assert!(normalize_value("setup", json!(true), None).is_err());
        assert!(normalize_value("start", json!(-1), None).is_err());
        assert!(normalize_value("start", json!(253_402_300_800_i64), None).is_err());
        assert!(normalize_value("social_shares", json!(true), None).is_err());
        assert!(normalize_value("mailgun_base_url", json!("file:///etc/passwd"), None).is_err());
        assert!(normalize_value("mailfrom_addr", json!("not-an-email"), None).is_err());
        assert!(normalize_value("mailfrom_addr", json!("CTF <ctf@example.org>"), None).is_ok());
        assert_eq!(
            normalize_value(
                "domain_whitelist",
                json!(" Example.org, *.Students.Example.org "),
                None,
            )
            .unwrap(),
            "example.org, *.students.example.org"
        );
        assert!(
            normalize_value("domain_blacklist", json!("*"), None).is_err(),
            "wildcards must identify a concrete subdomain suffix"
        );
        assert!(
            normalize_value(
                "mailgun_base_url",
                json!("https://api.mailgun.example/v3/event"),
                None
            )
            .is_ok()
        );

        let mut values = HashMap::from([
            ("start".to_owned(), "200".to_owned()),
            ("end".to_owned(), "100".to_owned()),
        ]);
        assert!(validate_cross_fields(&values).is_err());
        values.insert("end".to_owned(), "300".to_owned());
        values.insert("freeze".to_owned(), "400".to_owned());
        assert!(validate_cross_fields(&values).is_err());
        values.insert("freeze".to_owned(), "250".to_owned());
        values.insert("mail_ssl".to_owned(), "true".to_owned());
        values.insert("mail_tls".to_owned(), "true".to_owned());
        assert!(validate_cross_fields(&values).is_err());

        let mut verification = HashMap::from([("verify_emails".to_owned(), "true".to_owned())]);
        assert!(validate_cross_fields(&verification).is_err());
        verification.insert("mailfrom_addr".to_owned(), "ctf@example.org".to_owned());
        verification.insert("mail_provider".to_owned(), "smtp".to_owned());
        verification.insert("mail_server".to_owned(), "smtp.example.org".to_owned());
        assert!(validate_cross_fields(&verification).is_ok());
        verification.insert("mail_provider".to_owned(), "disabled".to_owned());
        assert!(validate_cross_fields(&verification).is_err());
    }

    #[test]
    fn empty_secret_means_keep_and_null_means_clear() {
        assert_eq!(
            normalize_value("mail_password", json!(""), Some("old")).unwrap(),
            "old"
        );
        assert_eq!(
            normalize_value("mail_password", Value::Null, Some("old")).unwrap(),
            ""
        );
        assert_eq!(
            normalize_value("mail_password", json!("new"), Some("old")).unwrap(),
            "new"
        );
    }

    #[test]
    fn missing_rows_have_typed_defaults_without_becoming_configured() {
        let paused = known_catalog_setting(setting("paused").unwrap(), None);
        assert!(!paused.configured);
        assert_eq!(paused.effective, Some(json!(false)));
        assert_eq!(paused.stored, None);
        let secret = known_catalog_setting(setting("registration_code").unwrap(), None);
        assert!(!secret.configured);
        assert_eq!(secret.value, None);
        assert_eq!(secret.effective, None);
        let creation = known_catalog_setting(setting("team_creation").unwrap(), None);
        assert_eq!(creation.effective, Some(json!(true)));
        let team_size = known_catalog_setting(setting("team_size").unwrap(), None);
        assert_eq!(team_size.effective, Some(json!(0)));
    }
}
