import pytest
from pydantic import ValidationError

from app.schemas_security import Authentication, FindingSeverity, SecurityGrade, SecurityRequest
from app.security import assess


def codes(response):
    return [f.code for f in response.findings]


def test_well_configured_network_is_secure():
    result = assess(SecurityRequest(authentication=Authentication.WPA2, cipher="CCMP", open_ports=[53, 80, 443],
                                    device_count=6, new_device_count=0, band="5"))

    assert result.score == 100
    assert result.grade == SecurityGrade.SECURE
    assert result.findings == []
    assert result.summary == "No encontramos problemas de seguridad en tu red."
    assert result.model_version == "security-1.0"


def test_open_network_is_critical_even_with_nothing_else_wrong():
    result = assess(SecurityRequest(authentication=Authentication.OPEN, open_ports=[443]))

    assert codes(result) == ["OPEN_NETWORK"]
    assert result.score <= 39
    assert result.grade == SecurityGrade.CRITICAL
    assert "contraseña" in result.summary


@pytest.mark.parametrize("auth, cipher, code, severity", [
    (Authentication.WEP, None, "WEP", FindingSeverity.CRITICAL),
    (Authentication.WPA, "TKIP", "WPA1", FindingSeverity.HIGH),
    (Authentication.WPA2, "TKIP", "TKIP", FindingSeverity.HIGH),
])
def test_weak_encryption(auth, cipher, code, severity):
    result = assess(SecurityRequest(authentication=auth, cipher=cipher))

    assert result.findings[0].code == code
    assert result.findings[0].severity == severity
    assert result.score <= 64


def test_unknown_authentication_is_informative_only():
    result = assess(SecurityRequest())

    assert codes(result) == ["AUTH_UNKNOWN"]
    assert result.score == 100


def test_dangerous_router_ports_are_reported_most_severe_first():
    result = assess(SecurityRequest(authentication=Authentication.WPA3,
                                    open_ports=[22, 21, 23, 445, 7547, 1900, 443]))

    assert codes(result) == ["PORT_TELNET", "PORT_SMB", "PORT_FTP", "PORT_TR069", "PORT_SSH", "PORT_UPNP"]
    assert result.score == min(100 - 25 - 20 - 15 - 10 - 5 - 5, 64)
    assert result.grade == SecurityGrade.CRITICAL


def test_admin_page_without_https():
    plain = assess(SecurityRequest(authentication=Authentication.WPA2, open_ports=[80]))
    with_https = assess(SecurityRequest(authentication=Authentication.WPA2, open_ports=[8080, 8443]))

    assert codes(plain) == ["ADMIN_HTTP"]
    assert plain.score == 90
    assert with_https.findings == []


def test_new_devices_lower_the_score_and_say_how_many():
    result = assess(SecurityRequest(authentication=Authentication.WPA2, device_count=9, new_device_count=2))

    assert codes(result) == ["NEW_DEVICES"]
    assert result.findings[0].title.startswith("2 ")
    assert result.score == 90


def test_band_and_congestion_are_advice_without_penalty():
    result = assess(SecurityRequest(authentication=Authentication.WPA2, band="2.4", channel=6,
                                    neighbors_same_channel=7))

    assert set(codes(result)) == {"BAND_24", "CHANNEL_CONGESTION"}
    assert all(f.severity == FindingSeverity.INFO for f in result.findings)
    assert result.score == 100
    assert "Canal 6" in result.findings[-1].title


def test_every_finding_explains_and_suggests_an_action():
    result = assess(SecurityRequest(authentication=Authentication.WEP, open_ports=[21, 22, 23, 80, 445, 1900, 7547],
                                    new_device_count=1, band="2.4", neighbors_same_channel=5))

    assert result.score == 0
    assert all(f.title and f.detail and f.action for f in result.findings)


def test_ports_are_validated_and_deduplicated():
    assert SecurityRequest(open_ports=[80, 80, 23]).open_ports == [23, 80]
    with pytest.raises(ValidationError):
        SecurityRequest(open_ports=[0])
    with pytest.raises(ValidationError):
        SecurityRequest(band="3")
