from pathlib import Path

import pytest

from wgdrift import conf
from wgdrift.models import HANDSHAKE_STALE_AFTER
from wgdrift.wireguard import WireGuardController, WireGuardError, parse_dump

FIXTURE = Path(__file__).parent / "fixtures" / "wg_dump.txt"


@pytest.fixture
def dump():
    return parse_dump(FIXTURE.read_text())


def test_parses_interfaces_in_order(dump):
    assert [i.name for i in dump] == ["wg0", "wg1"]
    wg0, wg1 = dump
    assert wg0.listen_port == 51820 and wg0.fwmark is None
    assert wg1.listen_port == 51821 and wg1.fwmark == 0xCA6C
    assert wg1.peers == ()


def test_private_key_is_discarded(dump):
    text = repr(dump)
    assert "PrivateKey" not in text and "otherPrivKey" not in text
    assert "pskPresent" not in text  # preshared key value is dropped too


def test_peer_fields(dump):
    wg0 = dump[0]
    alice = wg0.peers[0]
    assert alice.endpoint == "10.200.0.11:40123"
    assert [str(n) for n in alice.allowed_ips] == ["10.10.0.2/32"]
    assert alice.latest_handshake == 1757250000
    assert (alice.rx_bytes, alice.tx_bytes) == (123456, 654321)
    assert alice.persistent_keepalive is None and not alice.has_preshared_key

    bob = wg0.peers[1]
    assert bob.endpoint is None
    assert [str(n) for n in bob.allowed_ips] == ["10.10.0.3/32", "192.168.50.0/24"]
    assert bob.persistent_keepalive == 25 and bob.has_preshared_key


def test_handshake_state(dump):
    alice, bob = dump[0].peers
    now = 1757250000 + 30
    assert alice.is_connected(now)
    assert not alice.is_connected(now + HANDSHAKE_STALE_AFTER)
    assert bob.handshake_age(now) is None and not bob.is_connected(now)


def test_bindings_and_longest_prefix_owner(dump):
    wg0 = dump[0]
    bindings = wg0.bindings()
    assert set(bindings) == {p.public_key for p in wg0.peers}
    assert wg0.owner_of("10.10.0.2").public_key.startswith("alice")
    assert wg0.owner_of("192.168.50.7").public_key.startswith("bob")
    assert wg0.owner_of("10.10.0.99") is None


def test_single_interface_dump_without_name_column():
    text = "priv=\tpub=\t51820\toff\npeer=\t(none)\t(none)\t(none)\t0\t0\t0\toff\n"
    (iface,) = parse_dump(text, interface="wg0")
    assert iface.name == "wg0" and iface.peers[0].allowed_ips == ()


def test_malformed_dump_raises():
    with pytest.raises(WireGuardError):
        parse_dump("wg0\tonly\tthree\n")
    with pytest.raises(WireGuardError):
        parse_dump("wg0\tp\t(none)\t(none)\t(none)\t0\t0\t0\toff\n")  # peer before header


def test_controller_dry_run_records_commands():
    c = WireGuardController("wg0", dry_run=True)
    c.set_peer("KEY=", ["10.10.0.9/32"], persistent_keepalive=25)
    c.remove_peer("KEY=")
    assert c.executed == [
        ["wg", "set", "wg0", "peer", "KEY=", "allowed-ips", "10.10.0.9/32", "persistent-keepalive", "25"],
        ["wg", "set", "wg0", "peer", "KEY=", "remove"],
    ]


SAMPLE_CONF = """\
[Interface]
PrivateKey = gwPriv=
Address = 10.10.0.1/24
ListenPort = 51820
PostUp = nft -f /etc/nftables.conf

# Name: alice
[Peer]
PublicKey = alicePub=
AllowedIPs = 10.10.0.2/32

# Name: bob
[Peer]
PublicKey = bobPub=
AllowedIPs = 10.10.0.3/32, 192.168.50.0/24  # lab subnet
Endpoint = 10.200.0.12:51820
PersistentKeepalive = 25
"""


def test_conf_roundtrip():
    c = conf.parse(SAMPLE_CONF)
    assert c.listen_port == 51820 and c.address == ["10.10.0.1/24"]
    assert c.hooks == {"postup": ["nft -f /etc/nftables.conf"]}
    assert [p.name for p in c.peers] == ["alice", "bob"]
    assert c.peer("bobPub=").allowed_ips == ["10.10.0.3/32", "192.168.50.0/24"]
    assert conf.parse(conf.render(c)) == c


def test_conf_rejects_unknown_key():
    with pytest.raises(ValueError):
        conf.parse("[Interface]\nBogus = 1\n")
