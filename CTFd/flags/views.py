import os

from flask import Blueprint, send_from_directory

flags = Blueprint("flags", __name__)

# Directory containing the flag-type editor assets (create/edit templates) for
# the built-in flag types.
ASSETS_DIR = os.path.join(os.path.dirname(__file__), "assets")


@flags.route("/flags/assets/<path:path>")
def assets(path):
    return send_from_directory(ASSETS_DIR, path)
