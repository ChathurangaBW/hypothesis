import pytest
from hypothesis_pt.specs import import_operations, plan_hypotheses


def test_openapi_creates_banking_workflow_candidates_without_secrets():
    doc = {
        "openapi": "3.0.3", "servers": [{"url": "https://private.bank.example"}],
        "paths": {
            "/accounts/{accountId}": {"get": {"summary": "Account details", "security": [{"BearerAuth": []}],
                "requestBody": {"password": "NEVER_SAVE_ME"}}},
            "/payments/{paymentId}/approve": {"post": {"summary": "Approve payment"}},
            "/admin/reports": {"get": {"summary": "Admin reports"}},
        },
    }
    ops = import_operations("openapi", doc)
    assert len(ops) == 3
    assert "NEVER_SAVE_ME" not in str(ops)
    assert "private.bank.example" not in str(ops)
    plans = plan_hypotheses(ops)
    assert {"Object ownership / BOLA", "Separation of duties", "Workflow state integrity",
            "Function-level authorization / BFLA"} <= {p["title"] for p in plans}
    assert all(p["state"] == "proposed_unverified" for p in plans)


def test_postman_collection_discards_credentials_and_server():
    doc = {"item": [{"name": "Accounts", "item": [
        {"name": "Read account", "request": {"method": "GET",
         "url": "{{baseUrl}}/accounts/:id", "auth": {"bearer": [{"value": "secret"}]}}},
    ]}]}
    ops = import_operations("postman", doc)
    assert ops[0]["path"] == "/accounts/:id"
    assert "secret" not in str(ops)
    assert "{{baseUrl}}" not in str(ops)


def test_reject_external_path_and_oversized_documents():
    with pytest.raises(ValueError):
        import_operations("openapi", {"paths": {"//evil": {"get": {}}}})
    with pytest.raises(ValueError):
        import_operations("openapi", {"paths": {"/test": {"get": {}}}, "padding": "x"*1_000_000})


def test_only_supported_methods():
    ops = import_operations("openapi", {"paths": {"/health": {"get": {}, "trace": {}}}})
    assert [o["method"] for o in ops] == ["GET"]
