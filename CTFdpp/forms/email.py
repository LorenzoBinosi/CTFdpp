from wtforms import TextAreaField
from wtforms.validators import InputRequired

from CTFdpp.forms import BaseForm
from CTFdpp.forms.fields import SubmitField


class SendEmailForm(BaseForm):
    text = TextAreaField("Message", validators=[InputRequired()])
    submit = SubmitField("Send")
