from flask import render_template

from CTFdpp.admin import admin
from CTFdpp.models import Notifications
from CTFdpp.utils.decorators import admins_only


@admin.route("/admin/notifications")
@admins_only
def notifications():
    notifs = Notifications.query.order_by(Notifications.id.desc()).all()
    return render_template("admin/notifications.html", notifications=notifs)
