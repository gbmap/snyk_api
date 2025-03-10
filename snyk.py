import os
from argparse import ArgumentParser
from datetime import datetime
from enum import StrEnum
from utils import HttpMethod, api_call


class Command(StrEnum):
    LIST_GROUPS = "list_groups"
    LIST_ORGS = "list_organizations"
    LIST_PROJECTS = "list_projects"
    GET_PROJECT = "get_project"
    LIST_ISSUES = "list_issues"
    LIST_DEPENDENCIES = "list_dependencies"
    GET_ISSUES_BY_ORG_ID = "get_issues_by_org_id"
    GET_ISSUES_BY_GROUP_ID = "get_issues_by_group_id"
    GET_SBOM = "get_sbom"
    SEARCH_AUDIT = "search_audit"


def default_api_headers():
    return authorize({"Content-Type": "application/json; charset=utf-8"})


def authorize(headers):
    return headers | {"Authorization": f"token {os.getenv('SNYK_API_TOKEN')}"}


def snyk_api_call(method: HttpMethod, url: str, **kwargs):
    if not kwargs.get("headers", False):
        kwargs["headers"] = default_api_headers()
    return api_call(method, url, **kwargs)


def default_api_version():
    return "2025-01-01"
    return datetime.now().strftime("%Y-%m-%d")


def list_groups(version: str = default_api_version()):
    """https://apidocs.snyk.io/?version=2024-10-15#get-/groups"""
    return snyk_api_call(
        HttpMethod.GET, f"https://api.snyk.io/rest/groups?version={version}"
    )


def list_organizations():
    """https://docs.snyk.io/snyk-api/reference/organizations-v1#orgs"""
    return snyk_api_call(HttpMethod.GET, "https://api.snyk.io/v1/orgs")


def list_projects(org_id: str, version: str = default_api_version()):
    """https://docs.snyk.io/snyk-api/reference/projects#orgs-org_id-projects"""
    return snyk_api_call(
        HttpMethod.GET,
        f"https://api.snyk.io/rest/orgs/{org_id}/projects?version={version}",
    )


def get_project_by_id(
    org_id: str, project_id: str, version: str = default_api_version()
):
    """https://docs.snyk.io/snyk-api/reference/projects#orgs-org_id-projects-project_id"""
    return snyk_api_call(
        HttpMethod.GET,
        f"https://api.snyk.io/rest/orgs/{org_id}/projects/{project_id}?version={
            version
        }",
    )


def get_list_of_issues_v1(
    org_ids: list[str],
    start_date: datetime,
    end_date: datetime,
    page: int = 1,
    filters: dict = {},
):
    """https://docs.snyk.io/snyk-api/reference/reporting-api-v1#reporting-issues"""
    return snyk_api_call(
        HttpMethod.GET,
        "https://api.snyk.io/v1/reporting/issues"
        f"?from={start_date.strftime('%Y-%m-%d')}"
        f"&to={end_date.strftime('%Y-%m-%d')}",
        json={"filters": (filters | {"orgId": org_ids})},
    )


def get_list_of_latest_issues_v1(
    page: int = 1, page_size: int = 10, filters: dict | None = None
):
    """https://docs.snyk.io/snyk-api/reference/reporting-api-v1#reporting-issues-latest"""
    return snyk_api_call(
        HttpMethod.POST,
        f"https://api.snyk.io/v1/reporting/issues/latest?page={page}&page_size={
            page_size
        }",
        json={"filters": filters} if filters else None,
    )


def list_all_dependencies_v1(
    org_id: str, page: int = 0, page_size: int = 10, filters: dict | None = None
):
    return snyk_api_call(
        HttpMethod.POST,
        f"https://api.snyk.io/v1/org/{org_id}/dependencies?page={page}&perPage={
            page_size
        }",
        json={"filters": filters} if filters else None,
    )


def get_issues_by_org_id(org_id: str, version: str = default_api_version()):
    """https://docs.snyk.io/snyk-api/reference/issues#orgs-org_id-issues"""
    return snyk_api_call(
        HttpMethod.GET,
        f"https://api.snyk.io/rest/orgs/{org_id}/issues?version={version}",
    )


def get_issues_by_group_id(group_id: str, version: str = default_api_version()):
    """https://docs.snyk.io/snyk-api/reference/issues#groups-group_id-issues"""
    return snyk_api_call(
        HttpMethod.GET,
        f"https://api.snyk.io/rest/groups/{group_id}/issues?version={version}",
    )


def get_project_sbom_document(
    org_id: str, project_id: str, version: str = default_api_version()
):
    """https://docs.snyk.io/snyk-api/reference/sbom"""
    return snyk_api_call(
        HttpMethod.GET,
        f"https://api.snyk.io/rest/orgs/{org_id}/projects/{project_id}/sbom?version={
            version
        }",
    )


def remove_member_from_org(org_id: str, user_id: str):
    """https://docs.snyk.io/snyk-api/reference/organizations-v1#org-orgid-members-userid-1"""
    return snyk_api_call(
        HttpMethod.DELETE, f"https://api.snyk.io/v1/orgs/org/{org_id}/members/{user_id}"
    )


def update_member_role_in_org(org_id: str, project_id: str, version: str):
    """https://docs.snyk.io/snyk-api/reference/organizations-v1#org-orgid-members-update-userid"""
    pass


def search_org_audit_logs(
    org_id: str, version: str = default_api_version(), query_params: dict[str, str] = {}
):
    """https://docs.snyk.io/snyk-api/reference/audit-logs"""
    return snyk_api_call(
        HttpMethod.GET,
        add_query_params_to_url(
            f"https://api.snyk.io/rest/orgs/{org_id}/audit_logs/search",
            {"version": version} | query_params,
        ),
    )


def add_query_params_to_url(url: str, params: dict[str, str]):
    return url if len(params) == 0 else f"{url}{generate_url_params(params)}"


def generate_url_params(params: dict[str, str]):
    return f"?{'&'.join([f'{k}={v}' for k, v in params.items()])}"


def main():
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(Command.LIST_GROUPS)
    subparsers.add_parser(Command.LIST_ORGS)

    parser_cmd_list_projects = subparsers.add_parser(Command.LIST_PROJECTS)
    parser_cmd_list_projects.add_argument("org_id")

    parser_cmd_get_project = subparsers.add_parser(Command.GET_PROJECT)
    parser_cmd_get_project.add_argument("org_id")
    parser_cmd_get_project.add_argument("project_id")

    parser_cmd_list_issues = subparsers.add_parser(Command.LIST_ISSUES)
    parser_cmd_list_issues.add_argument("org_id")

    parser_cmd_get_issues_by_org_id = subparsers.add_parser(
        Command.GET_ISSUES_BY_ORG_ID
    )
    parser_cmd_get_issues_by_org_id.add_argument("org_id")

    parser_cmd_get_issues_by_group_id = subparsers.add_parser(
        Command.GET_ISSUES_BY_GROUP_ID
    )
    parser_cmd_get_issues_by_group_id.add_argument("group_id")

    parser_cmd_get_sbom = subparsers.add_parser(Command.GET_SBOM)
    parser_cmd_get_sbom.add_argument("org_id")
    parser_cmd_get_sbom.add_argument("project_id")

    parser_cmd_list_dependencies = subparsers.add_parser(Command.LIST_DEPENDENCIES)
    parser_cmd_list_dependencies.add_argument("org_id")

    parser_cmd_search_audit = subparsers.add_parser(Command.SEARCH_AUDIT)
    parser_cmd_search_audit.add_argument("org_id")

    args = parser.parse_args()

    match args.command:
        case Command.LIST_GROUPS:
            list_groups()
        case Command.LIST_ORGS:
            list_organizations()
        case Command.LIST_PROJECTS:
            list_projects(args.org_id)
        case Command.GET_PROJECT:
            get_project_by_id(args.org_id, args.project_id)
        case Command.LIST_ISSUES:
            get_list_of_issues_v1(
                [args.org_id], datetime(2025, 1, 1), datetime(2025, 2, 1)
            )
        case Command.GET_ISSUES_BY_ORG_ID:
            get_issues_by_org_id(args.org_id)
        case Command.GET_ISSUES_BY_GROUP_ID:
            get_issues_by_group_id(args.group_id)
        case Command.GET_SBOM:
            get_project_sbom_document(args.org_id, args.project_id)
        case Command.LIST_DEPENDENCIES:
            list_all_dependencies_v1(args.org_id)
        case Command.SEARCH_AUDIT:
            search_org_audit_logs(args.org_id)


if __name__ == "__main__":
    main()
