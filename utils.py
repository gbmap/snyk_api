from enum import IntEnum, auto
import requests
import json
from functools import wraps
from loguru import logger


class HttpMethod(IntEnum):
    GET = auto(),
    POST = auto(),
    PUT = auto(),
    DELETE = auto()


MAP_HTTP_METHOD_TO_FUNC = {
    HttpMethod.GET: requests.get,
    HttpMethod.POST: requests.post,
    HttpMethod.PUT: requests.put,
    HttpMethod.DELETE: requests.delete
}


def format_dict(data):
    return json.dumps(data, indent=True)


def debug_log_api_call(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        url = args[1]
        headers = kwargs.get("headers", None)
        json = kwargs.get("json", None)

        logger.debug(''.join([
            f"\n\nAPI Request\n\nURL: {url}",
            f"\nHeaders:\n{format_dict(headers)}" if headers else "",
            f"\nBody:\n{format_dict(json)}" if json else ""
        ]))

        response = f(*args, **kwargs)

        try:
            logger.debug(''.join([
                "\n\nAPI Response",
                f"\n{format_dict(response.json())}"
            ]))
        except Exception as e:
            logger.error(
                "Error parsing response:\n"
                f"Status Code: {response.status_code}\n"
                f"Response: {response.text}\n"
                f"Error: {e}"
            )
        return response
    return wrapper


@debug_log_api_call
def api_call(method: HttpMethod, url: str, **kwargs):
    return MAP_HTTP_METHOD_TO_FUNC[method](
        url,
        **kwargs
    )
