import argparse

from pysec import cli, port_scanner


def test_dispatcher_lists_all_tools():
    assert set(cli.TOOLS) == {"port", "net", "ssh", "hash", "dir", "subdomain", "web"}


def test_every_tool_exposes_cli_interface():
    for name, (module_name, _help) in cli.TOOLS.items():
        module = cli.load_tool(module_name)
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
