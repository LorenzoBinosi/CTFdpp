from CTFd.models import Users
from sqlalchemy import Column, String

def patch_users():
    if not hasattr(Users, 'token'):
        Users.user_token = Column(String(64), unique=True)
