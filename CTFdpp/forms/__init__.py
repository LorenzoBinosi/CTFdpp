from wtforms import Form
from wtforms.csrf.core import CSRF


class CTFdCSRF(CSRF):
    def generate_csrf_token(self, csrf_token_field):
        from flask import session

        return session.get("nonce")


class BaseForm(Form):
    class Meta:
        csrf = True
        csrf_class = CTFdCSRF
        csrf_field_name = "nonce"


class _FormsWrapper:
    pass


Forms = _FormsWrapper()

from CTFdpp.forms import auth  # noqa: I001 isort:skip
from CTFdpp.forms import self  # noqa: I001 isort:skip
from CTFdpp.forms import teams  # noqa: I001 isort:skip
from CTFdpp.forms import setup  # noqa: I001 isort:skip
from CTFdpp.forms import submissions  # noqa: I001 isort:skip
from CTFdpp.forms import users  # noqa: I001 isort:skip
from CTFdpp.forms import challenges  # noqa: I001 isort:skip
from CTFdpp.forms import language  # noqa: I001 isort:skip
from CTFdpp.forms import notifications  # noqa: I001 isort:skip
from CTFdpp.forms import config  # noqa: I001 isort:skip
from CTFdpp.forms import pages  # noqa: I001 isort:skip
from CTFdpp.forms import awards  # noqa: I001 isort:skip
from CTFdpp.forms import email  # noqa: I001 isort:skip

Forms.auth = auth
Forms.self = self
Forms.teams = teams
Forms.setup = setup
Forms.submissions = submissions
Forms.users = users
Forms.challenges = challenges
Forms.language = language
Forms.notifications = notifications
Forms.config = config
Forms.pages = pages
Forms.awards = awards
Forms.email = email
