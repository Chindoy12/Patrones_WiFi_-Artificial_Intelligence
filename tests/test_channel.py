import pytest

from app.channel import MIN_GAIN, band_of, overlap, recommend
from app.schemas_channel import ChannelCount, ChannelRequest


def counts(**by_channel):
    return [ChannelCount(channel=int(ch[1:]), networks=n) for ch, n in by_channel.items()]


def test_crowded_2_4_channel_moves_to_the_calm_one():
    result = recommend(ChannelRequest(band="2.4", channel=6, channel_counts=counts(c1=3, c6=4, c11=0)))

    assert result.should_change
    assert result.current_load == 4
    assert result.recommended_channel == 11
    assert result.recommended_load == 0
    assert "canal 6" in result.summary and "canal 11" in result.summary
    assert "11" in result.action
    assert result.model_version == "channel-1.0"
    assert [o.channel for o in result.options] == [1, 6, 11]


def test_partially_overlapping_neighbours_count_less():
    # channel 3 is 2 away from 1 (overlap 0.6) and 3 away from 6 (overlap 0.4)
    result = recommend(ChannelRequest(band="2.4", channel=1, channel_counts=counts(c3=5)))

    options = {o.channel: o.load for o in result.options}
    assert options == {1: 3.0, 6: 2.0, 11: 0.0}
    assert result.recommended_channel == 11


def test_off_grid_2_4_channel_is_moved_even_for_a_small_gain():
    result = recommend(ChannelRequest(band="2.4", channel=3, channel_counts=counts(c1=1)))

    assert result.should_change
    assert result.recommended_channel in (6, 11)
    assert "1, 6 y 11" in result.summary


def test_small_gain_is_not_worth_disconnecting_everyone():
    # channel 1: one neighbour (load 1); channel 6: only part of a neighbour on 9 (load 0.4)
    result = recommend(ChannelRequest(band="2.4", channel=1, channel_counts=counts(c1=1, c9=1)))

    assert result.recommended_channel == 6
    assert 0 < result.current_load - result.recommended_load < MIN_GAIN
    assert not result.should_change
    assert result.action is None
    assert "buen canal" in result.summary


def test_free_channel_says_so():
    result = recommend(ChannelRequest(band="5", channel=44, channel_counts=counts(c149=2)))

    assert not result.should_change
    assert result.current_load == 0
    assert "libre" in result.summary


def test_5ghz_neighbours_in_the_same_80mhz_block_count_half():
    result = recommend(ChannelRequest(band="5", channel=36, channel_counts=counts(c36=2, c44=2)))

    options = {o.channel: o.load for o in result.options}
    assert options[36] == 3.0  # 2 on the same channel + 2 * 0.5 in the block
    assert options[149] == 0.0
    assert result.should_change and result.recommended_channel == 149


def test_neighbours_on_the_other_band_do_not_count():
    result = recommend(ChannelRequest(band="5", channel=36, channel_counts=counts(c1=9, c6=9, c11=9)))

    assert result.current_load == 0
    assert not result.should_change


def test_band_is_inferred_from_the_channel():
    assert recommend(ChannelRequest(channel=11, channel_counts=counts(c11=5))).band == "2.4"
    assert recommend(ChannelRequest(channel=149, channel_counts=counts(c149=5))).band == "5"


def test_without_neighbour_data_there_is_nothing_to_recommend():
    result = recommend(ChannelRequest(band="2.4", channel=6))

    assert result.recommended_channel is None
    assert not result.should_change
    assert "redes vecinas" in result.summary


def test_6ghz_is_not_compared():
    result = recommend(ChannelRequest(band="6", channel=37, channel_counts=counts(c37=4)))

    assert not result.should_change
    assert "6 GHz" in result.summary


def test_unknown_current_channel_still_suggests_the_calmest():
    result = recommend(ChannelRequest(band="2.4", channel_counts=counts(c1=2, c6=0, c11=3)))

    assert result.recommended_channel == 6
    assert not result.should_change


@pytest.mark.parametrize("a, b, expected", [(1, 1, 1.0), (1, 6, 0.0), (1, 3, 0.6), (6, 11, 0.0)])
def test_overlap_2_4(a, b, expected):
    assert overlap("2.4", a, b) == pytest.approx(expected)


@pytest.mark.parametrize("channel, band", [(1, "2.4"), (14, "2.4"), (36, "5"), (165, "5"), (200, None)])
def test_band_of(channel, band):
    assert band_of(channel) == band


def test_ties_keep_the_current_channel():
    result = recommend(ChannelRequest(band="2.4", channel=6, channel_counts=counts(c1=2, c6=2, c11=2)))

    assert result.recommended_channel == 6
    assert not result.should_change


def test_summary_speaks_in_whole_networks():
    result = recommend(ChannelRequest(band="2.4", channel=6, channel_counts=counts(c1=3, c3=1, c6=4)))

    assert result.current_load == 4.4  # the exact weighting stays available for the bars
    assert result.summary == ("Tu router usa el canal 6, donde hay 4 redes vecinas y 1 más en un canal encimado. "
                              "En el canal 11 no hay ninguna.")


def test_summary_when_the_best_channel_also_has_neighbours():
    result = recommend(ChannelRequest(band="2.4", channel=6, channel_counts=counts(c1=2, c6=5, c11=1)))

    assert result.recommended_channel == 11
    assert result.summary == "Tu router usa el canal 6, donde hay 5 redes vecinas. En el canal 11 hay 1 red vecina."
