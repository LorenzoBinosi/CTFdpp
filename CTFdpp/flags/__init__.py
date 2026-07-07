from CTFdpp.flags.base import BaseFlag, FlagException
from CTFdpp.flags.regex import CTFdRegexFlag
from CTFdpp.flags.static import CTFdStaticFlag

FLAG_CLASSES = {
    "static": CTFdStaticFlag,
    "regex": CTFdRegexFlag,
}


def get_flag_class(class_id):
    cls = FLAG_CLASSES.get(class_id)
    if cls is None:
        raise KeyError
    return cls


__all__ = [
    "BaseFlag",
    "FlagException",
    "CTFdStaticFlag",
    "CTFdRegexFlag",
    "FLAG_CLASSES",
    "get_flag_class",
]
