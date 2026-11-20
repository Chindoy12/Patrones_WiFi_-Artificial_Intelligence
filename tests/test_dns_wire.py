"""The DNS wire format shared by the mDNS discovery and the DNS of the router (agent/dns_wire.py)."""
import struct

import pytest

from agent import device_discovery as discovery
from agent import dns_wire
from agent import router_sources as routers
from agent import wifisense_agent as agent


def test_a_name_written_and_read_back_is_the_same_name():
    packet = dns_wire.dns_name("iPhone-de-Ana.local")
    assert packet == b"\x0diPhone-de-Ana\x05local\x00"
    assert dns_wire.read_name(packet, 0) == ("iPhone-de-Ana.local", len(packet))


def test_a_compression_pointer_continues_the_name_elsewhere_in_the_packet():
    packet = dns_wire.dns_name("local") + b"\x04Sala\xc0\x00"
    assert dns_wire.read_name(packet, 7) == ("Sala.local", len(packet))


@pytest.mark.parametrize("packet, offset", [
    (b"\x05lo", 0),                # a label cut short
    (b"\xc0", 0),                  # a pointer cut short
    (b"\xc0\x00", 0),              # a pointer to itself: it would loop forever
])
def test_a_malformed_name_raises_value_error_instead_of_reading_past_the_packet(packet, offset):
    with pytest.raises(ValueError):
        dns_wire.read_name(packet, offset)


def test_every_module_of_the_agent_uses_the_same_reader():
    assert agent.read_name is routers.read_name is discovery.read_name is dns_wire.read_name
    assert agent.dns_name is discovery.dns_name is dns_wire.dns_name


def test_an_mdns_answer_whose_name_loops_is_ignored_not_a_crash():
    looping = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c"
    assert agent.parse_mdns_ptr(looping) is None
    assert discovery.parse_mdns_records(looping) == []
