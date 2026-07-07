from sqlalchemy.exc import OperationalError, ProgrammingError

from CTFdpp.utils.exports.serializers import JSONSerializer


def freeze_export(result, fileobj):
    try:
        query = result
        serializer = JSONSerializer(query, fileobj)
        serializer.serialize()
    except (OperationalError, ProgrammingError) as e:
        raise OperationalError("Invalid query: %s" % e)
