from marshmallow import fields

from CTFdpp.models import Comments, ma
from CTFdpp.schemas.users import UserSchema


class CommentSchema(ma.ModelSchema):
    class Meta:
        model = Comments
        include_fk = True
        dump_only = ("id", "date", "html", "author", "author_id", "type")

    author = fields.Nested(UserSchema(only=("name",)))
    html = fields.String()
