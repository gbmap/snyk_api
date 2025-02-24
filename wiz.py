import base64
import json
import requests
from datetime import datetime
import os
from utils import api_call, HttpMethod
from loguru import logger

HEADERS_AUTH = {"Content-Type": "application/x-www-form-urlencoded"}
HEADERS = {"Content-Type": "application/json"}

CLIENT_ID = os.getenv("WIZ_CLIENT_ID")
CLIENT_SECRET = os.getenv("WIZ_CLIENT_SECRET")
API_TOKEN = os.getenv("WIZ_API_TOKEN")
API_DC = os.getenv("WIZ_API_DC")


def default_api_headers(api_token: str):
    return HEADERS | {"Authorization": f"Bearer {api_token}"}


def load_query(
    query_name: str, variable_values: dict, queries_dir: str = "wiz_queries"
) -> tuple[str, str | None]:
    with open(os.path.join(queries_dir, f"{query_name}.graphql"), "r") as f:
        query = f.read()

    with open(os.path.join(queries_dir, f"{query_name}.vars.graphql")) as f:
        variables = f.read()

    variables = variables.strip("\n")[1:-1].format(**variable_values)
    variables = "{" + variables + "}"
    return query, json.loads(variables)


def request_wiz_api_token(
    client_id: str, client_secret: str, auth_headers: str
) -> tuple[str, str]:
    auth_payload = {
        "grant_type": "client_credentials",
        "audience": "wiz-api",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    response = api_call(
        HttpMethod.POST,
        "https://auth.app.wiz.io/oauth/token",
        headers=auth_headers,
        data=auth_payload,
    )
    response_json = response.json()

    token = response_json.get("access_token")
    response_json_decoded = json.loads(
        base64.standard_b64decode(pad_base64(token.split(".")[1]))
    )
    dc = response_json_decoded["dc"]
    return token, dc


def wiz_api_call(method: HttpMethod, url: str, **kwargs):
    if not kwargs.get("headers", None):
        kwargs["headers"] = default_api_headers(kwargs.get("api_token"))
    data = {"variables": kwargs.get("variables"), "query": kwargs.get("query")}
    return api_call(method, url, headers=kwargs.get("headers"), json=data)


def get_issues(
    api_token: str,
    dc: str,
    start_date: datetime,
    end_date: datetime,
    issue_type: str = "OPEN_ISSUES",
    interval: str = "DAY",
    filter_by: dict = {"sourceRule": {}},
):
    query, variables = load_query(
        "get_issues",
        {
            "filterBy": json.dumps(filter_by),
            "startDate": str(start_date),
            "endDate": str(end_date),
            "type": issue_type,
            "interval": interval,
        },
    )
    return wiz_api_call(
        HttpMethod.GET,
        f"https://api.{dc}.app.wiz.io/graphql",
        query=query,
        variables=variables,
        api_token=api_token,
    )


def issues_table(api_token: str, dc: str, first: int):
    query, variables = load_query("issues_table", {"first": first})
    return wiz_api_call(
        HttpMethod.POST,
        f"https://api.{dc}.app.wiz.io/graphql",
        query=query,
        variables=variables,
        api_token=api_token,
    )


def pad_base64(data):
    """Makes sure base64 data is padded"""
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += "=" * (4 - missing_padding)
    return data


def main():
    if API_TOKEN is None or API_DC is None:
        logger.info("Requesting WIZ token")
        token, dc = request_wiz_api_token(CLIENT_ID, CLIENT_SECRET, HEADERS_AUTH)
        logger.debug(f"{token=} {dc=}")
        logger.success("API Token obtained")
    else:
        logger.success("Using cached Wiz API token and dc.")
        token, dc = API_TOKEN, API_DC

    # get_issues(token, dc, datetime(2021, 1, 1), datetime(2022, 1, 1))
    issues_table(token, dc, 5)

    # result = query_wiz_api(QUERY, VARIABLES, dc)
    # print(result)  # your data is here!


if __name__ == "__main__":
    main()
