from marshmallow import fields

from CTFdpp.models import Submissions, ma
from CTFdpp.schemas.challenges import ChallengeSchema
from CTFdpp.schemas.teams import TeamSchema
from CTFdpp.schemas.users import UserSchema
from CTFdpp.utils import string_types


class SubmissionSchema(ma.ModelSchema):
    challenge = fields.Nested(ChallengeSchema, only=["id", "name", "category", "value"])
    user = fields.Nested(UserSchema, only=["id", "name"])
    team = fields.Nested(TeamSchema, only=["id", "name"])

    class Meta:
        model = Submissions
        include_fk = True
        dump_only = ("id",)

    views = {
        "admin": [
            "provided",
            "ip",
            "challenge_id",
            "challenge",
            "user",
            "team",
            "date",
            "type",
            "id",
        ],
        "user": ["challenge_id", "challenge", "user", "team", "date", "type", "id"],
        "self": [
            "challenge_id",
            "challenge",
            "user",
            "team",
            "date",
            "type",
            "id",
            "provided",
        ],
    }

    def __init__(self, view=None, *args, **kwargs):
        if view:
            if isinstance(view, string_types):
                kwargs["only"] = self.views[view]
            elif isinstance(view, list):
                kwargs["only"] = view

        super(SubmissionSchema, self).__init__(*args, **kwargs)
