from flask import Blueprint, render_template, redirect, url_for
from CTFd.plugins import register_user_registered_hook, register_plugin_assets_directory
from CTFd.models import Users, db
import secrets

from . import models

def generate_token(user):
    if not getattr(user, 'token', None):
        token = secrets.token_urlsafe(32)
        user.user_token = token
        db.session.commit()

def user_registered_hook(user):
    generate_token(user)

user_token_bp = Blueprint("user_token", __name__, template_folder="templates")

@user_token_bp.route("/token")
def token_view():
    from CTFd.utils.user import get_current_user
    user = get_current_user()
    if not user:
        return redirect(url_for("auth.login"))
    return render_template("token.html", token=user.user_token)

def load(app):
    models.patch_users()
    register_user_registered_hook(user_registered_hook)
    app.register_blueprint(user_token_bp)
    register_plugin_assets_directory(app, base_path="/plugins/user_token/assets")
