import pytest

from app import quality
from app.schemas_quality import MetricStatus, QualityGrade, QualityRequest


def score(**values):
    return quality.score(QualityRequest(**values))


def test_fast_stable_connection_is_excellent_and_good_for_everything():
    result = score(latency_ms=12, jitter_ms=2, packet_loss_pct=0, download_mbps=300, upload_mbps=60)

    assert result.score >= 95
    assert result.grade == QualityGrade.EXCELLENT
    assert all(a.suitable for a in result.activities)
    assert result.tips == []


def test_one_very_bad_metric_caps_the_overall_score():
    result = score(latency_ms=12, jitter_ms=2, packet_loss_pct=12, download_mbps=300, upload_mbps=60)

    loss = next(m for m in result.metrics if m.metric == "packet_loss")
    assert loss.score == 0 and loss.status == MetricStatus.POOR
    assert result.score <= quality.BOTTLENECK_MARGIN
    assert result.grade == QualityGrade.POOR
    assert "Se pierden datos" in result.tips[0]


def test_download_is_judged_against_the_contracted_speed():
    full = score(latency_ms=20, jitter_ms=4, download_mbps=280, contracted_mbps=300)
    half = score(latency_ms=20, jitter_ms=4, download_mbps=90, contracted_mbps=300)

    assert full.contracted_ratio == 0.93
    assert next(m for m in full.metrics if m.metric == "download").score == 100
    assert next(m for m in half.metrics if m.metric == "download").score < 65
    assert half.score < full.score


def test_activities_follow_their_requirements():
    result = score(latency_ms=90, jitter_ms=12, packet_loss_pct=0.5, download_mbps=15, upload_mbps=4)
    by_activity = {a.activity: a.suitable for a in result.activities}

    assert by_activity == {"BROWSING": True, "VIDEO_CALLS": True, "STREAMING_HD": True, "STREAMING_4K": False,
                           "GAMING": False}


def test_unmeasured_core_metrics_leave_the_activity_undecided():
    result = score(latency_ms=30, jitter_ms=5)
    by_activity = {a.activity: a.suitable for a in result.activities}

    assert by_activity["STREAMING_4K"] is None  # no download measured
    assert by_activity["GAMING"] is True
    assert {m.metric for m in result.metrics} == {"latency", "jitter"}


def test_browser_test_without_packet_loss_still_decides_activities():
    result = score(latency_ms=25, jitter_ms=4, download_mbps=80, upload_mbps=15)

    assert all(a.suitable is True for a in result.activities)


def test_measured_packet_loss_is_still_required():
    result = score(latency_ms=25, jitter_ms=4, packet_loss_pct=4, download_mbps=80, upload_mbps=15)
    by_activity = {a.activity: a.suitable for a in result.activities}

    assert by_activity["BROWSING"] is True and by_activity["VIDEO_CALLS"] is False


@pytest.mark.parametrize("value, expected", [(20, 100), (35, 92.5), (400, 0), (1000, 0), (5, 100)])
def test_latency_curve_interpolates_between_breakpoints(value, expected):
    assert quality.curve_score(quality.CURVES["latency"], value) == pytest.approx(expected)


def test_grade_limits():
    assert [quality.grade_of(s) for s in (85, 84, 70, 69, 50, 49)] == [
        QualityGrade.EXCELLENT, QualityGrade.GOOD, QualityGrade.GOOD, QualityGrade.FAIR, QualityGrade.FAIR,
        QualityGrade.POOR]


def test_contracted_speed_without_download_is_rejected():
    with pytest.raises(ValueError):
        QualityRequest(latency_ms=20, jitter_ms=3, contracted_mbps=100)
