from __future__ import annotations

import pytest

from core.validators import ValidationError, safe_profile_name, validate_port_spec, validate_target, validate_time_value


def test_validate_target_accepts_common_forms() -> None:
    assert validate_target("192.168.1.1") == "192.168.1.1"
    assert validate_target("10.0.0.0/24") == "10.0.0.0/24"
    assert validate_target("example.com") == "example.com"
    assert validate_target("192.168.1.1-50") == "192.168.1.1-50"


def test_validate_target_rejects_empty() -> None:
    with pytest.raises(ValidationError):
        validate_target("")


def test_validate_port_spec() -> None:
    assert validate_port_spec("22,80,1000-2000") == "22,80,1000-2000"
    with pytest.raises(ValidationError):
        validate_port_spec("200-100")
    with pytest.raises(ValidationError):
        validate_port_spec("70000")


def test_validate_time_and_profile_name() -> None:
    assert validate_time_value("500ms") == "500ms"
    assert validate_time_value("30s") == "30s"
    assert safe_profile_name("Web Scan!") == "Web-Scan"
    with pytest.raises(ValidationError):
        validate_time_value("soon")
