import re

from CTFdpp.flags.base import BaseFlag, FlagException


class CTFdRegexFlag(BaseFlag):
    name = "regex"
    templates = {  # Nunjucks templates used for key editing & viewing
        "create": "/flags/assets/regex/create.html",
        "update": "/flags/assets/regex/edit.html",
    }

    @staticmethod
    def compare(chal_key_obj, provided):
        saved = chal_key_obj.content
        data = chal_key_obj.data

        try:
            if data == "case_insensitive":
                res = re.match(saved, provided, re.IGNORECASE)
            else:
                res = re.match(saved, provided)
        except re.error as e:
            raise FlagException("Regex parse error occured") from e

        return res and res.group() == provided
