import pytest
from datetime import datetime, timedelta

import snyk


@pytest.fixture
def org_id():
    return snyk.list_organizations().json()["orgs"][0]["id"]


@pytest.fixture
def group_id():
    return snyk.list_groups().json()["data"][0]['id']


@pytest.fixture
def project_id(org_id):
    return snyk.list_projects(org_id).json()["projects"][0]["id"]


def validate_response(response, expected_status_code: int = 200):
    assert response.status_code == expected_status_code


def test_list_organizations():
    validate_response(snyk.list_organizations())


def test_list_projects(org_id):
    validate_response(snyk.list_projects(org_id))


def test_get_project_by_id(org_id, project_id):
    validate_response(snyk.get_project_by_id(org_id, project_id))


def test_get_list_of_issues_v1(org_id):
    validate_response(
        snyk.get_list_of_issues_v1(
            [org_id], datetime.now() - timedelta(days=100), datetime.now()
        )
    )


def test_get_list_of_latest_issues_v1(org_id):
    validate_response(snyk.get_list_of_latest_issues_v1(org_id))


def test_list_all_dependencies_v1(org_id):
    validate_response(snyk.list_all_dependencies_v1(org_id))


def test_get_issues_by_org_id(org_id):
    validate_response(snyk.get_issues_by_org_id(org_id))


def test_get_issues_by_group_id(group_id):
    validate_response(snyk.get_issues_by_group_id(group_id))


def test_get_project_sbom_document(org_id, project_id):
    validate_response(snyk.get_project_sbom_document(org_id, project_id))


# def test_remove_member_from_org(org_id):
#     validate_response(snyk.remove_member_from_org(org_id))

# def test_update_member_role_in_org(org_id):
#     validate_response(snyk.update_member_role_in_org(org_id))

def test_search_org_audit_logs(org_id):
    validate_response(snyk.search_org_audit_logs(org_id))
