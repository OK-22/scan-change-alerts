import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from scan import compare, parse_nmap_xml, render_report  # noqa: E402

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
    </ports>
  </host>
  <host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="10.0.0.6" addrtype="ipv4"/></host>
</nmaprun>"""


def test_parse_keeps_only_open_ports_on_hosts_that_are_up():
    result = parse_nmap_xml(SAMPLE_XML)
    assert result == {"10.0.0.5": {"22/tcp": "ssh", "80/tcp": "http"}, "10.0.0.6": {}}


def test_no_change_means_no_alert():
    base = {"h": {"22/tcp": "ssh"}}
    d = compare(base, base)
    assert not d["alert"] and not d["changed"]


def test_new_open_port_raises_alert():
    d = compare({"h": {"22/tcp": "ssh"}}, {"h": {"22/tcp": "ssh", "8099/tcp": "http"}})
    assert d["alert"]
    assert d["new_ports"] == {"h": {"8099/tcp": "http"}}


def test_new_host_with_open_ports_raises_alert():
    d = compare({"a": {}}, {"a": {}, "b": {"443/tcp": "https"}})
    assert d["alert"]
    assert d["new_hosts"] == ["b"]
    assert d["new_ports"] == {"b": {"443/tcp": "https"}}


def test_closed_port_is_reported_but_does_not_alert():
    d = compare({"h": {"22/tcp": "ssh", "80/tcp": "http"}}, {"h": {"22/tcp": "ssh"}})
    assert not d["alert"]
    assert d["changed"]
    assert d["closed_ports"] == {"h": {"80/tcp": "http"}}


def test_report_lists_new_ports():
    d = compare({"h": {}}, {"h": {"8099/tcp": "http"}})
    report = render_report(d, ["h"], "2026-10-08 06:17")
    assert "New open ports" in report and "8099/tcp" in report
