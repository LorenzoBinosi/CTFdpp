mod account_events;
mod administration;
mod bootstrap;
mod challenges;
mod configuration;
mod content;
mod create_idempotency;
mod exports;
mod flag_policy;
mod mail;
mod objects;
mod participant_tokens;
mod runtimes;
mod scoreboard;
mod sessions;
pub(crate) mod ssh_hosts;
mod statistics;
mod team_accounts;
mod tokens;
mod user_accounts;
pub(crate) mod user_mode_transition;
mod users;
mod views;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};
use serde::Serialize;

use crate::AppState;

#[derive(Serialize)]
pub(crate) struct Success<T> {
    pub(crate) success: bool,
    pub(crate) data: T,
}

impl<T> Success<T> {
    pub(crate) fn new(data: T) -> Self {
        Self {
            success: true,
            data,
        }
    }
}

pub(crate) fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/bootstrap", get(bootstrap::get))
        .route("/api/v1/views/challenges", get(views::challenges))
        .route("/api/v1/views/admin/overview", get(views::admin_overview))
        .route(
            "/api/v1/views/admin/configuration",
            get(views::admin_configuration),
        )
        .route(
            "/api/v1/views/admin/user-mode-transition",
            get(user_mode_transition::preview),
        )
        .route(
            "/api/v1/challenges",
            get(challenges::list).post(challenges::create),
        )
        .route("/api/v1/challenges/attempt", post(challenges::attempt))
        .route(
            "/api/v1/challenges/{challenge_id}/instance",
            get(runtimes::challenge_instance)
                .post(runtimes::ensure_instance)
                .delete(runtimes::terminate_challenge_instance),
        )
        .route(
            "/api/v1/challenges/{challenge_id}",
            get(challenges::detail)
                .patch(challenges::update)
                .delete(challenges::delete_challenge),
        )
        .route("/api/v1/challenges/types", get(content::challenge_types))
        .route(
            "/api/v1/challenges/{challenge_id}/solves",
            get(content::challenge_solves),
        )
        .route(
            "/api/v1/challenges/{challenge_id}/files",
            get(content::challenge_files),
        )
        .route(
            "/api/v1/challenges/{challenge_id}/tags",
            get(content::challenge_tags),
        )
        .route(
            "/api/v1/challenges/{challenge_id}/topics",
            get(content::challenge_topics),
        )
        .route(
            "/api/v1/challenges/{challenge_id}/hints",
            get(content::challenge_hints),
        )
        .route(
            "/api/v1/challenges/{challenge_id}/flags",
            get(content::challenge_flags),
        )
        .route(
            "/api/v1/challenges/{challenge_id}/requirements",
            get(content::challenge_requirements),
        )
        .route(
            "/api/v1/challenges/{challenge_id}/ratings",
            get(content::challenge_ratings).put(content::rate_challenge),
        )
        .route(
            "/api/v1/challenges/{challenge_id}/solution",
            get(content::challenge_solution),
        )
        .route(
            "/api/v1/hints",
            get(content::list_hints).post(content::create_hint),
        )
        .route(
            "/api/v1/hints/{hint_id}",
            get(content::get_hint)
                .patch(content::update_hint)
                .delete(content::delete_hint),
        )
        .route(
            "/api/v1/solutions",
            get(content::list_solutions).post(content::create_solution),
        )
        .route(
            "/api/v1/solutions/{solution_id}",
            get(content::get_solution)
                .patch(content::update_solution)
                .delete(content::delete_solution),
        )
        .route(
            "/api/v1/unlocks",
            get(content::list_unlocks).post(content::unlock),
        )
        .route(
            "/api/v1/notifications",
            get(content::list_notifications).post(content::create_notification),
        )
        .route(
            "/api/v1/notifications/{notification_id}",
            get(content::get_notification).delete(content::delete_notification),
        )
        .route(
            "/api/v1/configs",
            get(administration::list_configs)
                .post(administration::create_config)
                .patch(administration::patch_configs),
        )
        .route(
            "/api/v1/configs/registration-emails",
            get(administration::list_registration_emails)
                .post(administration::create_registration_email),
        )
        .route(
            "/api/v1/configs/user-mode-transition",
            post(user_mode_transition::execute),
        )
        .route(
            "/api/v1/configs/registration-emails/import",
            post(administration::import_registration_emails)
                .layer(DefaultBodyLimit::max(5 * 1024 * 1024 + 64 * 1024)),
        )
        .route(
            "/api/v1/configs/registration-emails/{entry_id}",
            axum::routing::delete(administration::delete_registration_email),
        )
        .route(
            "/api/v1/configs/fields",
            get(administration::list_fields).post(administration::create_field),
        )
        .route(
            "/api/v1/configs/fields/{field_id}",
            get(administration::get_field)
                .patch(administration::update_field)
                .delete(administration::delete_field),
        )
        .route(
            "/api/v1/configs/{config_key}",
            get(administration::get_config).patch(administration::update_config),
        )
        .route(
            "/api/v1/pages",
            get(administration::list_pages).post(administration::create_page),
        )
        .route(
            "/api/v1/pages/by-route/{route}",
            get(administration::get_page_by_route),
        )
        .route(
            "/api/v1/pages/{page_id}",
            get(administration::get_page)
                .patch(administration::update_page)
                .delete(administration::delete_page),
        )
        .route(
            "/api/v1/brackets",
            get(administration::list_brackets).post(administration::create_bracket),
        )
        .route(
            "/api/v1/brackets/{bracket_id}",
            axum::routing::patch(administration::update_bracket)
                .delete(administration::delete_bracket),
        )
        .route(
            "/api/v1/admin/challenge-categories",
            get(administration::list_challenge_categories)
                .post(administration::create_challenge_category),
        )
        .route(
            "/api/v1/admin/challenge-categories/{category_id}",
            axum::routing::delete(administration::delete_challenge_category),
        )
        .route(
            "/api/v1/flags",
            get(administration::list_flags).post(administration::create_flag),
        )
        .route("/api/v1/flags/types", get(administration::flag_types))
        .route(
            "/api/v1/flags/types/{type_name}",
            get(administration::flag_type),
        )
        .route(
            "/api/v1/flags/{flag_id}",
            get(administration::get_flag)
                .patch(administration::update_flag)
                .delete(administration::delete_flag),
        )
        .route(
            "/api/v1/tags",
            get(administration::list_tags).post(administration::create_tag),
        )
        .route(
            "/api/v1/tags/{tag_id}",
            get(administration::get_tag)
                .patch(administration::update_tag)
                .delete(administration::delete_tag),
        )
        .route(
            "/api/v1/topics",
            get(administration::list_topics)
                .post(administration::create_topic_relation)
                .delete(administration::delete_topic_relation),
        )
        .route(
            "/api/v1/topics/{topic_id}",
            get(administration::get_topic).delete(administration::delete_topic),
        )
        .route(
            "/api/v1/awards",
            get(administration::list_awards).post(administration::create_award),
        )
        .route(
            "/api/v1/awards/{award_id}",
            get(administration::get_award).delete(administration::delete_award),
        )
        .route(
            "/api/v1/comments",
            get(administration::list_comments).post(administration::create_comment),
        )
        .route(
            "/api/v1/comments/{comment_id}",
            axum::routing::delete(administration::delete_comment),
        )
        .route(
            "/api/v1/submissions",
            get(administration::list_submissions).post(administration::create_submission),
        )
        .route(
            "/api/v1/submissions/{submission_id}",
            get(administration::get_submission)
                .patch(administration::update_submission)
                .delete(administration::delete_submission),
        )
        .route("/api/v1/exports/raw", post(exports::raw))
        .route(
            "/api/v1/storage/uploads",
            post(objects::initiate_upload)
                .layer(DefaultBodyLimit::max(objects::MAX_UPLOAD_BODY_BYTES)),
        )
        .route(
            "/api/v1/storage/objects/{object_id}",
            get(objects::object_detail).delete(objects::delete_object),
        )
        .route(
            "/api/v1/storage/objects/{object_id}/complete",
            post(objects::complete_upload),
        )
        .route(
            "/api/v1/storage/objects/{object_id}/download",
            get(objects::download_grant),
        )
        .route(
            "/api/v1/users/me",
            get(users::current_user).patch(user_accounts::update_self),
        )
        .route(
            "/api/v1/users",
            get(user_accounts::list).post(user_accounts::create),
        )
        .route(
            "/api/v1/users/{user_id}",
            get(user_accounts::detail)
                .patch(user_accounts::update_admin)
                .delete(user_accounts::delete),
        )
        .route("/api/v1/users/{user_id}/email", post(mail::email_user))
        .route(
            "/api/v1/users/me/verification-email",
            post(mail::send_self_verification_email),
        )
        .route(
            "/api/v1/email-verifications/confirm",
            post(mail::confirm_email),
        )
        .route(
            "/api/v1/users/me/submissions",
            get(account_events::user_me_submissions),
        )
        .route(
            "/api/v1/users/me/solves",
            get(account_events::user_me_solves),
        )
        .route("/api/v1/users/me/fails", get(account_events::user_me_fails))
        .route(
            "/api/v1/users/me/awards",
            get(account_events::user_me_awards),
        )
        .route(
            "/api/v1/users/{user_id}/solves",
            get(account_events::user_solves),
        )
        .route(
            "/api/v1/users/{user_id}/fails",
            get(account_events::user_fails),
        )
        .route(
            "/api/v1/users/{user_id}/awards",
            get(account_events::user_awards),
        )
        .route(
            "/api/v1/teams",
            get(team_accounts::list).post(team_accounts::create),
        )
        .route(
            "/api/v1/teams/me",
            get(team_accounts::current)
                .post(team_accounts::create_current)
                .patch(team_accounts::update_current)
                .delete(team_accounts::delete_current),
        )
        .route("/api/v1/teams/me/join", post(team_accounts::join_current))
        .route(
            "/api/v1/teams/me/members",
            post(team_accounts::current_invite),
        )
        .route(
            "/api/v1/teams/{team_id}",
            get(team_accounts::detail)
                .patch(team_accounts::update_admin)
                .delete(team_accounts::delete_admin),
        )
        .route(
            "/api/v1/teams/{team_id}/members",
            get(team_accounts::list_members)
                .post(team_accounts::add_member)
                .delete(team_accounts::remove_member),
        )
        .route(
            "/api/v1/teams/me/solves",
            get(account_events::team_me_solves),
        )
        .route("/api/v1/teams/me/fails", get(account_events::team_me_fails))
        .route(
            "/api/v1/teams/me/awards",
            get(account_events::team_me_awards),
        )
        .route(
            "/api/v1/teams/{team_id}/solves",
            get(account_events::team_solves),
        )
        .route(
            "/api/v1/teams/{team_id}/fails",
            get(account_events::team_fails),
        )
        .route(
            "/api/v1/teams/{team_id}/awards",
            get(account_events::team_awards),
        )
        .route(
            "/api/v1/tokens",
            get(tokens::list_tokens).post(tokens::create_token),
        )
        .route(
            "/api/v1/tokens/{token_id}",
            get(tokens::get_token).delete(tokens::delete_token),
        )
        .route(
            "/api/v1/participant-token",
            get(participant_tokens::get).post(participant_tokens::rotate),
        )
        .route("/api/v1/sessions/users", get(sessions::users))
        .route("/api/v1/scoreboard", get(scoreboard::list))
        .route("/api/v1/scoreboard/top/{count}", get(scoreboard::top))
        .route("/api/v1/statistics/users", get(statistics::users))
        .route(
            "/api/v1/statistics/users/{column}",
            get(statistics::user_property),
        )
        .route("/api/v1/statistics/teams", get(statistics::teams))
        .route(
            "/api/v1/statistics/submissions/{column}",
            get(statistics::submission_property),
        )
        .route(
            "/api/v1/statistics/challenges/solves",
            get(statistics::challenge_solves),
        )
        .route(
            "/api/v1/statistics/challenges/solves/percentages",
            get(statistics::challenge_solve_percentages),
        )
        .route(
            "/api/v1/statistics/challenges/{column}",
            get(statistics::challenge_property),
        )
        .route(
            "/api/v1/statistics/scores/distribution",
            get(statistics::score_distribution),
        )
        .route(
            "/api/v1/statistics/progression/matrix",
            get(statistics::progression_matrix),
        )
        .route("/api/v1/sessions", get(sessions::list))
        .route("/api/v1/sessions/revoke", post(sessions::revoke_all))
        .route(
            "/api/v1/sessions/users/{user_id}/revoke",
            post(sessions::revoke_user),
        )
        .route(
            "/api/v1/sessions/{management_id}/revoke",
            post(sessions::revoke_one),
        )
        .route("/api/v1/instances", get(runtimes::history))
        .route("/api/v1/instances/{instance_id}", get(runtimes::detail))
        .route(
            "/api/v1/instances/{instance_id}/events",
            get(runtimes::events),
        )
        .route(
            "/api/v1/instances/{instance_id}/terminate",
            post(runtimes::terminate_instance),
        )
        .route(
            "/api/v1/instances/{instance_id}/extend",
            post(runtimes::extend_instance),
        )
        .route(
            "/api/v1/admin/runtime/settings/private-challenges",
            get(runtimes::get_private_challenges_setting)
                .patch(runtimes::update_private_challenges_setting),
        )
        .route(
            "/api/v1/admin/challenges/{challenge_id}/runtime",
            get(runtimes::get_challenge_runtime).put(runtimes::put_challenge_runtime),
        )
        .route(
            "/api/v1/admin/runtime/servers",
            get(runtimes::list_remote_servers).post(runtimes::create_remote_server),
        )
        .route(
            "/api/v1/admin/runtime/servers/{server_id}",
            get(runtimes::get_remote_server)
                .patch(runtimes::update_remote_server)
                .delete(runtimes::disable_remote_server),
        )
        .route(
            "/api/v1/admin/runtime/instances",
            get(runtimes::admin_instances),
        )
        .route(
            "/api/v1/admin/runtime/instances/{instance_id}/reconcile",
            post(runtimes::reconcile_instance),
        )
        .route(
            "/api/v1/admin/ssh/hosts",
            get(ssh_hosts::list_hosts).post(ssh_hosts::create_host),
        )
        .route(
            "/api/v1/admin/ssh/hosts/{host_id}",
            get(ssh_hosts::get_host).delete(ssh_hosts::delete_host),
        )
        .route(
            "/api/v1/admin/ssh/hosts/{host_id}/identity/retry",
            post(ssh_hosts::retry_identity),
        )
        .route(
            "/api/v1/admin/ssh/hosts/{host_id}/host-key/trust",
            post(ssh_hosts::trust_host_key),
        )
        .route(
            "/api/v1/admin/ssh/hosts/{host_id}/tickets",
            post(ssh_hosts::issue_ticket),
        )
        .route_layer(middleware::from_fn_with_state(
            state,
            crate::auth::optional_authenticated_activity,
        ))
}
