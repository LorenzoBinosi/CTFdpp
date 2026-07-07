import os

from flask import Blueprint, redirect, render_template, request, send_from_directory, url_for
from flask_babel import lazy_gettext as _l

from CTFdpp.constants.config import ChallengeVisibilityTypes, Configs
from CTFdpp.utils.config import is_teams_mode
from CTFdpp.utils.dates import ctf_ended, ctf_paused, ctf_started
from CTFdpp.utils.decorators import (
    during_ctf_time_only,
    require_complete_profile,
    require_verified_emails,
)
from CTFdpp.utils.decorators.visibility import check_challenge_visibility
from CTFdpp.utils.helpers import get_errors, get_infos
from CTFdpp.utils.user import authed, get_current_team

challenges = Blueprint("challenges", __name__)

# Directory containing the challenge-type editor/view assets (create/update/view
# templates and scripts) for the built-in challenge types.
ASSETS_DIR = os.path.join(os.path.dirname(__file__), "assets")


@challenges.route("/challenges/assets/<path:path>")
def assets(path):
    return send_from_directory(ASSETS_DIR, path)


@challenges.route("/challenges", methods=["GET"])
@require_complete_profile
@during_ctf_time_only
@require_verified_emails
@check_challenge_visibility
def listing():
    if (
        Configs.challenge_visibility == ChallengeVisibilityTypes.PUBLIC
        and authed() is False
    ):
        pass
    else:
        if is_teams_mode() and get_current_team() is None:
            return redirect(url_for("teams.private", next=request.full_path))

    infos = get_infos()
    errors = get_errors()

    if Configs.challenge_visibility == ChallengeVisibilityTypes.ADMINS:
        infos.append(_l("Challenge Visibility is set to Admins Only"))

    if ctf_started() is False:
        errors.append(_l("%(ctf_name)s has not started yet", ctf_name=Configs.ctf_name))

    if ctf_paused() is True:
        infos.append(_l("%(ctf_name)s is paused", ctf_name=Configs.ctf_name))

    if ctf_ended() is True:
        infos.append(_l("%(ctf_name)s has ended", ctf_name=Configs.ctf_name))

    return render_template("challenges.html", infos=infos, errors=errors)
