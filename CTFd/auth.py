from flask import Blueprint, abort
from flask import current_app as app
from flask import redirect, render_template, request, session, url_for
from flask_babel import lazy_gettext as _l

from CTFd.cache import cache, clear_user_session
from CTFd.exceptions.email import (
    UserConfirmTokenInvalidException,
    UserResetPasswordTokenInvalidException,
)
from CTFd.models import Brackets, UserFieldEntries, UserFields, Users, db
from CTFd.utils import config, email, get_app_config, get_config
from CTFd.utils import user as current_user
from CTFd.utils import validators
from CTFd.utils.config import can_send_mail, is_teams_mode
from CTFd.utils.crypto import verify_password
from CTFd.utils.decorators import ratelimit
from CTFd.utils.decorators.visibility import check_registration_visibility
from CTFd.utils.helpers import get_errors, markup
from CTFd.utils.logging import log
from CTFd.utils.security.auth import generate_preset_admin, login_user, logout_user
from CTFd.utils.security.email import (
    remove_email_confirm_token,
    remove_reset_password_token,
    verify_email_confirm_token,
    verify_reset_password_token,
)
from CTFd.utils.validators import ValidationError

auth = Blueprint("auth", __name__)


@auth.route("/confirm", methods=["POST", "GET"])
@auth.route("/confirm/<data>", methods=["POST", "GET"])
@ratelimit(method="POST", limit=10, interval=60)
def confirm(data=None):
    # If we can't send mails our behavior depends on verify_emails
    if not can_send_mail():
        if get_config("verify_emails") is False:
            return redirect(url_for("challenges.listing"))
        else:
            return render_template(
                "confirm.html",
                errors=[
                    "Email verification is enabled but email sending isn't available. Please contact an admin to confirm your account"
                ],
            )

    # User is confirming email account
    if data and request.method == "GET":
        try:
            user_email = verify_email_confirm_token(data)
        except (UserConfirmTokenInvalidException):
            return render_template(
                "confirm.html",
                errors=["Your confirmation link is invalid, please generate a new one"],
            )

        user = Users.query.filter_by(email=user_email).first_or_404()
        if user.verified:
            return redirect(url_for("views.settings"))

        if (
            get_app_config("EMAIL_CONFIRMATION_REQUIRE_INTERACTION")
            and request.args.get("interaction") is None
        ):
            button = """<button style="margin-top: 3rem; padding: 1rem;" onclick="
                let u = new window.URL(window.location.href);
                u.searchParams.set('interaction', '1');
                window.location.href = u;">Click Here to Confirm Email</button>"""
            return render_template("page.html", content=button)

        user.verified = True
        log(
            "registrations",
            format="[{date}] {ip} - successful confirmation for {name}",
            name=user.name,
        )
        db.session.commit()
        remove_email_confirm_token(data)
        clear_user_session(user_id=user.id)
        # Only send this registration notification if we are preventing access to registered users only
        if get_config("verify_emails"):
            email.successful_registration_notification(user.email)
        db.session.close()
        if current_user.authed():
            return redirect(url_for("challenges.listing"))
        return redirect(url_for("auth.login"))

    # User is trying to start or restart the confirmation flow
    if current_user.authed() is False:
        return redirect(url_for("auth.login"))

    user = Users.query.filter_by(id=session["id"]).first_or_404()
    if user.verified:
        return redirect(url_for("views.settings"))

    if data is None:
        if request.method == "POST":
            # User wants to resend their confirmation email
            email.verify_email_address(user.email)
            log(
                "registrations",
                format="[{date}] {ip} - {name} initiated a confirmation email resend",
                name=user.name,
            )
            return render_template(
                "confirm.html", infos=[f"Confirmation email sent to {user.email}!"]
            )
        elif request.method == "GET":
            # User has been directed to the confirm page
            return render_template("confirm.html")


@auth.route("/reset_password", methods=["POST", "GET"])
@auth.route("/reset_password/<data>", methods=["POST", "GET"])
@ratelimit(method="POST", limit=10, interval=60)
def reset_password(data=None):
    if config.can_send_mail() is False and data is None:
        return render_template(
            "reset_password.html",
            errors=[
                markup(
                    "This CTF is not configured to send email.<br> Please contact an organizer to have your password reset."
                )
            ],
        )

    if data is not None:
        try:
            email_address = verify_reset_password_token(data)
        except (UserResetPasswordTokenInvalidException):
            return render_template(
                "reset_password.html",
                errors=["Your reset link is invalid, please generate a new one"],
            )

        if request.method == "GET":
            return render_template("reset_password.html", mode="set")
        if request.method == "POST":
            password = request.form.get("password", "").strip()
            user = Users.query.filter_by(email=email_address).first_or_404()

            pass_short = len(password) == 0
            if pass_short:
                return render_template(
                    "reset_password.html", errors=[_l("Please pick a longer password")]
                )

            password_min_length = int(get_config("password_min_length", default=0))
            pass_min = len(password) < password_min_length
            if pass_min:
                return render_template(
                    "reset_password.html",
                    errors=[
                        _l(
                            f"Password must be at least {password_min_length} characters"
                        )
                    ],
                )

            user.password = password
            user.change_password = False
            db.session.commit()
            remove_reset_password_token(data)
            clear_user_session(user_id=user.id)
            log(
                "logins",
                format="[{date}] {ip} - successful password reset for {name}",
                name=user.name,
            )
            db.session.close()
            email.password_change_alert(user.email)
            return redirect(url_for("auth.login"))

    if request.method == "POST":
        email_address = request.form["email"].strip()
        user = Users.query.filter_by(email=email_address).first()

        get_errors()

        if not user:
            return render_template(
                "reset_password.html",
                infos=[
                    _l(
                        "If that account exists you will receive an email, please check your inbox"
                    )
                ],
            )

        # Preferably this would be in a pipeline or multi but the benefit is minor
        limit = cache.inc(f"reset_password_attempt_user_{user.id}")
        cache.expire(f"reset_password_attempt_user_{user.id}", 180)
        if limit > 5:
            return render_template(
                "reset_password.html",
                errors=[
                    _l("Too many password reset attempts. Please try again later.")
                ],
            )
        email.forgot_password(email_address)

        return render_template(
            "reset_password.html",
            infos=[
                _l(
                    "If that account exists you will receive an email, please check your inbox"
                )
            ],
        )
    return render_template("reset_password.html")


@auth.route("/register", methods=["POST", "GET"])
@check_registration_visibility
@ratelimit(method="POST", limit=10, interval=5)
def register():
    errors = get_errors()
    if current_user.authed():
        return redirect(url_for("challenges.listing"))

    num_users_limit = int(get_config("num_users", default=0))
    num_users = Users.query.filter_by(banned=False, hidden=False).count()
    if num_users_limit and num_users >= num_users_limit:
        abort(
            403,
            description=f"Reached the maximum number of users ({num_users_limit}).",
        )

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email_address = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        website = request.form.get("website")
        affiliation = request.form.get("affiliation")
        country = request.form.get("country")
        registration_code = str(request.form.get("registration_code", ""))
        bracket_id = request.form.get("bracket_id", None)

        name_len = len(name) == 0
        names = (
            Users.query.add_columns(Users.name, Users.id).filter_by(name=name).first()
        )
        emails = (
            Users.query.add_columns(Users.email, Users.id)
            .filter_by(email=email_address)
            .first()
        )
        pass_short = len(password) == 0
        pass_long = len(password) > 128
        valid_email = validators.validate_email(email_address)
        team_name_email_check = validators.validate_email(name)

        password_min_length = int(get_config("password_min_length", default=0))
        pass_min = len(password) < password_min_length

        if get_config("registration_code"):
            if (
                registration_code.lower()
                != str(get_config("registration_code", default="")).lower()
            ):
                errors.append(_l("The registration code you entered was incorrect"))

        # Process additional user fields
        fields = {}
        for field in UserFields.query.all():
            fields[field.id] = field

        entries = {}
        for field_id, field in fields.items():
            value = request.form.get(f"fields[{field_id}]", "").strip()
            if field.required is True and (value is None or value == ""):
                errors.append(_l("Please provide all required fields"))
                break

            if field.field_type == "boolean":
                entries[field_id] = bool(value)
            else:
                entries[field_id] = value

        if country:
            try:
                validators.validate_country_code(country)
                valid_country = True
            except ValidationError:
                valid_country = False
        else:
            valid_country = True

        if website:
            valid_website = validators.validate_url(website)
        else:
            valid_website = True

        if affiliation:
            valid_affiliation = len(affiliation) < 128
        else:
            valid_affiliation = True

        if bracket_id:
            valid_bracket = bool(
                Brackets.query.filter_by(id=bracket_id, type="users").first()
            )
        else:
            if Brackets.query.filter_by(type="users").count():
                valid_bracket = False
            else:
                valid_bracket = True

        if not valid_email:
            errors.append(_l("Please enter a valid email address"))
        if email.check_email_is_whitelisted(email_address) is False:
            errors.append(_l("Your email address is not from an allowed domain"))
        if email.check_email_is_blacklisted(email_address) is True:
            errors.append(_l("Your email address is not from an allowed domain"))
        if names:
            errors.append(_l("That user name is already taken"))
        if team_name_email_check is True:
            errors.append(_l("Your user name cannot be an email address"))
        if emails:
            errors.append(_l("That email has already been used"))
        if pass_short:
            errors.append(_l("Pick a longer password"))
        if password_min_length and pass_min:
            errors.append(
                _l(f"Password must be at least {password_min_length} characters")
            )
        if pass_long:
            errors.append(_l("Pick a shorter password"))
        if name_len:
            errors.append(_l("Pick a longer user name"))
        if valid_website is False:
            errors.append(
                _l("Websites must be a proper URL starting with http or https")
            )
        if valid_country is False:
            errors.append(_l("Invalid country"))
        if valid_affiliation is False:
            errors.append(_l("Please provide a shorter affiliation"))
        if valid_bracket is False:
            errors.append(_l("Please provide a valid bracket"))

        if len(errors) > 0:
            return render_template(
                "register.html",
                errors=errors,
                name=request.form["name"],
                email=request.form["email"],
                password=request.form["password"],
            )
        else:
            with app.app_context():
                user = Users(
                    name=name,
                    email=email_address,
                    password=password,
                    bracket_id=bracket_id,
                )

                if website:
                    user.website = website
                if affiliation:
                    user.affiliation = affiliation
                if country:
                    user.country = country

                db.session.add(user)
                db.session.commit()
                db.session.flush()

                for field_id, value in entries.items():
                    entry = UserFieldEntries(
                        field_id=field_id, value=value, user_id=user.id
                    )
                    db.session.add(entry)
                db.session.commit()

                login_user(user)

                if request.args.get("next") and validators.is_safe_url(
                    request.args.get("next")
                ):
                    return redirect(request.args.get("next"))

                if config.can_send_mail() and get_config(
                    "verify_emails"
                ):  # Confirming users is enabled and we can send email.
                    log(
                        "registrations",
                        format="[{date}] {ip} - {name} registered (UNCONFIRMED) with {email}",
                        name=user.name,
                        email=user.email,
                    )
                    email.verify_email_address(user.email)
                    db.session.close()
                    return redirect(url_for("auth.confirm"))
                else:  # Don't care about confirming users
                    if (
                        config.can_send_mail()
                    ):  # We want to notify the user that they have registered.
                        email.successful_registration_notification(user.email)

        log(
            "registrations",
            format="[{date}] {ip} - {name} registered with {email}",
            name=user.name,
            email=user.email,
        )
        db.session.close()

        if is_teams_mode():
            return redirect(url_for("teams.private"))

        return redirect(url_for("challenges.listing"))
    else:
        return render_template("register.html", errors=errors)


@auth.route("/login", methods=["POST", "GET"])
@ratelimit(method="POST", limit=10, interval=5)
def login():
    errors = get_errors()
    if request.method == "POST":
        name = request.form["name"]

        # Check for preset admin credentials first
        preset_admin_name = get_app_config("PRESET_ADMIN_NAME")
        preset_admin_email = get_app_config("PRESET_ADMIN_EMAIL")
        preset_admin_password = get_app_config("PRESET_ADMIN_PASSWORD")

        if preset_admin_name and preset_admin_email and preset_admin_password:
            password = request.form.get("password", "")
            # Check if credentials match preset admin
            if (
                name == preset_admin_name or name == preset_admin_email
            ) and password == preset_admin_password:
                admin = generate_preset_admin()
                if admin:
                    login_user(user=admin)
                    return redirect(url_for("challenges.listing"))
                else:
                    errors.append(
                        "Preset admin user could not be created. Please contact an administrator"
                    )
                    return render_template("login.html", errors=errors)

        # Check if the user submitted an email address or a team name
        if validators.validate_email(name) is True:
            user = Users.query.filter_by(email=name).first()
        else:
            user = Users.query.filter_by(name=name).first()

        if user:
            if user.password is None:
                errors.append(
                    "Your account was registered with a 3rd party authentication provider. "
                    "Please try logging in with a configured authentication provider."
                )
                return render_template("login.html", errors=errors)

            if user and verify_password(request.form["password"], user.password):
                session.regenerate()

                login_user(user)
                log("logins", "[{date}] {ip} - {name} logged in", name=user.name)

                db.session.close()
                if request.args.get("next") and validators.is_safe_url(
                    request.args.get("next")
                ):
                    return redirect(request.args.get("next"))
                return redirect(url_for("challenges.listing"))

            else:
                # This user exists but the password is wrong
                log(
                    "logins",
                    "[{date}] {ip} - submitted invalid password for {name}",
                    name=user.name,
                )
                errors.append("Your username or password is incorrect")
                db.session.close()
                return render_template("login.html", errors=errors)
        else:
            # This user just doesn't exist
            log("logins", "[{date}] {ip} - submitted invalid account information")
            errors.append("Your username or password is incorrect")
            db.session.close()
            return render_template("login.html", errors=errors)
    else:
        db.session.close()
        return render_template("login.html", errors=errors)


@auth.route("/logout")
def logout():
    if current_user.authed():
        logout_user()
    return redirect(url_for("views.static_html"))
