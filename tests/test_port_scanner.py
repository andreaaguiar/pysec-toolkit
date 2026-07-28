import port_scanner


def test_parse_ports_range():
    assert port_scanner.parse_ports("1-1000") == (1, 1000)


def test_parse_ports_single():
    assert port_scanner.parse_ports("80") == (80, 80)


def test_parse_ports_full():
    assert port_scanner.parse_ports("1-65535") == (1, 65535)
