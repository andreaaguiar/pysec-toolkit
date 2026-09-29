from pysec import network_scanner


def test_save_to_file_writes_hosts(tmp_path):
    output = tmp_path / "results.txt"
    scan_results = {
        "results": [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
            {"ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:ff"},
        ],
        "scan_time": 1.23,
        "hosts_found": 2,
    }

    network_scanner.save_to_file(str(output), scan_results)

    content = output.read_text()
    assert "192.168.1.1" in content
    assert "00:11:22:33:44:55" in content
    assert "192.168.1.2" in content
    assert "Found 2 active hosts" in content


def test_save_to_file_empty_results(tmp_path):
    output = tmp_path / "results.txt"
    scan_results = {"results": [], "scan_time": 0.5, "hosts_found": 0}

    network_scanner.save_to_file(str(output), scan_results)

    assert "Found 0 active hosts" in output.read_text()
