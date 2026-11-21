from app.csv_utils import parse_csv_rows, find_field


def test_find_field_matches_case_and_separator_variants():
    row = {"IP address": "10.0.0.1"}
    for candidate in ("ip address", "IP_ADDRESS", "Ip-Address", "ipaddress"):
        assert find_field(row, [candidate]) == "10.0.0.1", f"failed for candidate {candidate!r}"


def test_find_field_returns_none_when_nothing_matches():
    assert find_field({"hostname": "web01"}, ["ip", "ip address"]) is None


def test_find_field_skips_blank_values_and_tries_next_candidate():
    row = {"ip": "", "ip address": "10.0.0.9"}
    assert find_field(row, ["ip", "ip address"]) == "10.0.0.9"


def test_parse_csv_rows_basic():
    text = "name,ip,status\nweb01,10.0.0.1,active\n"
    assert parse_csv_rows(text) == [{"name": "web01", "ip": "10.0.0.1", "status": "active"}]


def test_parse_csv_rows_disambiguates_duplicate_headers():
    text = "name,tag,tag\nweb01,env:prod,owner:infra\n"
    rows = parse_csv_rows(text)
    assert rows == [{"name": "web01", "tag": "env:prod", "tag_1": "owner:infra"}]


def test_parse_csv_rows_pads_short_rows():
    text = "name,ip,status\nweb01,10.0.0.1\n"
    rows = parse_csv_rows(text)
    assert rows == [{"name": "web01", "ip": "10.0.0.1", "status": ""}]


def test_parse_csv_rows_keeps_extra_values_on_long_rows():
    text = "name,ip\nweb01,10.0.0.1,extra-value,another-extra\n"
    rows = parse_csv_rows(text)
    assert rows == [{"name": "web01", "ip": "10.0.0.1", "extra_1": "extra-value", "extra_2": "another-extra"}]


def test_parse_csv_rows_empty_file():
    assert parse_csv_rows("") == []


def test_parse_csv_rows_header_only():
    assert parse_csv_rows("name,ip,status\n") == []
