from .build import build_exp
from .session import cd_remote_tmp
from .upload import upload


def build_only():
    return build_exp()


def upload_and_cd(io):
    uploaded = upload(io)
    if uploaded:
        cd_remote_tmp(io)
    return uploaded
