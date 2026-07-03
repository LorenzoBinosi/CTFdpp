from CTFd.challenges.base import CHALLENGE_CLASSES, BaseChallenge
from CTFd.models import Challenges


class CTFdStandardChallenge(BaseChallenge):
    id = "standard"  # Unique identifier used to register challenges
    name = "standard"  # Name of a challenge type
    templates = {  # Templates used for each aspect of challenge editing & viewing
        "create": "/challenges/assets/standard/create.html",
        "update": "/challenges/assets/standard/update.html",
        "view": "/challenges/assets/standard/view.html",
    }
    scripts = {  # Scripts that are loaded when a template is loaded
        "create": "/challenges/assets/standard/create.js",
        "update": "/challenges/assets/standard/update.js",
        "view": "/challenges/assets/standard/view.js",
    }
    challenge_model = Challenges


CHALLENGE_CLASSES["standard"] = CTFdStandardChallenge
