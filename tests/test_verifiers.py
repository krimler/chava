from chava.verifiers import sql_safe_verifier, pii_clean_verifier, schema_validator


def test_sql_safe_accepts_safe_query():
    assert sql_safe_verifier("SELECT * FROM users WHERE id=1;", "") in ("accept", "conditional")


def test_sql_safe_rejects_drop_table():
    assert sql_safe_verifier("DROP TABLE users;", "") == "reject"


def test_sql_safe_rejects_delete_without_where():
    assert sql_safe_verifier("DELETE FROM users;", "") == "reject"


def test_sql_safe_conditional_unbounded_select():
    assert sql_safe_verifier("SELECT * FROM large_table;", "") in ("accept", "conditional")


def test_pii_clean_rejects_phone_number():
    assert pii_clean_verifier("Call me at 555-123-4567", "") == "reject"


def test_pii_clean_rejects_email():
    assert pii_clean_verifier("Contact: test@example.com", "") == "reject"


def test_pii_clean_rejects_ssn():
    assert pii_clean_verifier("SSN: 123-45-6789", "") == "reject"


def test_pii_clean_accepts_clean_text():
    assert pii_clean_verifier("This is clean text", "") == "accept"


def test_schema_validator_accepts_valid():
    assert schema_validator({"id": 123, "name": "John"}, "") == "accept"


def test_schema_validator_rejects_missing_field():
    assert schema_validator({"id": 123}, "") == "reject"


def test_schema_validator_rejects_wrong_type():
    assert schema_validator({"id": "no", "name": "John"}, "") == "reject"


def test_schema_validator_rejects_non_dict():
    assert schema_validator("not_a_dict", "") == "reject"
