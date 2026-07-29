import argparse

import port_scanner

import pysec


def test_dispatcher_lists_all_tools():
    assert set(pysec.TOOLS) == {"port", "net", "ssh", "hash", "dir", "subdomain", "web"}


def test_every_tool_exposes_cli_interface():
    for name, (relative_path, _help) in pysec.TOOLS.items():
        module = pysec.load_tool(relative_path)
        assert callable(getattr(module, "add_arguments", None)), f"{name} missing add_arguments"
        assert callable(getattr(module, "run", None)), f"{name} missing run"


def test_standardized_flags_parse():
    parser = argparse.ArgumentParser()
    port_scanner.add_arguments(parser)
    args = parser.parse_args(["10.0.0.1", "-T", "50", "--timeout", "0.3", "-p", "1-100"])
    assert args.target == "10.0.0.1"
    assert args.threads == 50
    assert args.timeout == 0.3
    assert args.ports == "1-100"
