from ipaddress import ip_network
from pathlib import Path

from wgdrift.routing import RoutingState, parse_links, parse_routes, parse_rules

FIX = Path(__file__).parent / "fixtures" / "gateway"


def state(ip_forward=True):
    return RoutingState(ip_forward, parse_routes((FIX / "routes.json").read_text()),
                        parse_links((FIX / "addrs.json").read_text()), parse_rules((FIX / "rules.json").read_text()))


def test_parse_routes_and_links():
    st = state()
    assert st.lookup("10.100.0.10").dev == "eth0"
    assert st.lookup("10.10.0.2").dev == "wg0"
    assert st.lookup("8.8.8.8").dst == ip_network("0.0.0.0/0")
    wg0 = st.link("wg0")
    assert wg0.up and wg0.operstate == "UNKNOWN"   # UP flag, not operstate, is the signal
    assert str(wg0.addresses[0]) == "10.10.0.1/24"
    assert st.interface_for(ip_network("10.100.0.0/24")).name == "eth0"
    assert st.nonstandard_rules() == []


def test_longest_prefix_and_metric():
    st = RoutingState(True, parse_routes('[{"dst":"10.0.0.0/8","dev":"a"},{"dst":"10.1.0.0/16","dev":"b","metric":100},'
                                          '{"dst":"10.1.0.0/16","dev":"c","metric":50}]'))
    assert st.lookup("10.1.2.3").dev == "c"
    assert st.lookup("10.2.0.1").dev == "a"
    assert st.lookup("192.168.1.1") is None
