from CTFd.challenges.base import (
    CHALLENGE_CLASSES,
    BaseChallenge,
    ChallengeResponse,
    calculate_value,
    get_chal_class,
)

# Import the built-in challenge types so they register themselves into
# CHALLENGE_CLASSES and their models (e.g. the dynamic challenge) are mapped.
# NOTE: the user-facing blueprint lives in CTFd.challenges.views and is imported
# directly by the app factory; we deliberately do not import it here because it
# pulls in modules that touch ``current_app`` at import time.
from CTFd.challenges import dynamic, standard  # noqa: F401,E402

__all__ = [
    "CHALLENGE_CLASSES",
    "BaseChallenge",
    "ChallengeResponse",
    "calculate_value",
    "get_chal_class",
]
