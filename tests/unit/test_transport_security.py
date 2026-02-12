import logging
import sys
from unittest.mock import AsyncMock
from unittest.mock import patch

import pytest

from postgres_mcp.server import parse_bool_env
from postgres_mcp.server import parse_comma_separated
from postgres_mcp.server import resolve_dns_protection_enabled


class TestParseBoolEnv:
    @pytest.mark.parametrize("value", ["true", "True", "TRUE", "1", "yes", "y", "on", " true ", " YES "])
    def test_truthy_values(self, value: str):
        assert parse_bool_env(value) is True

    @pytest.mark.parametrize("value", ["false", "False", "FALSE", "0", "no", "n", "off", " false ", " NO "])
    def test_falsy_values(self, value: str):
        assert parse_bool_env(value) is False

    @pytest.mark.parametrize("value", ["", "maybe", "2", "truthy", "nope"])
    def test_unrecognized_values(self, value: str):
        assert parse_bool_env(value) is None


class TestResolveDnsProtectionEnabled:
    def test_env_false_disables_protection(self):
        assert resolve_dns_protection_enabled("false", cli_disable_flag=False) is False

    def test_env_true_enables_protection(self):
        assert resolve_dns_protection_enabled("true", cli_disable_flag=True) is True

    def test_env_none_with_cli_disable_returns_false(self):
        assert resolve_dns_protection_enabled(None, cli_disable_flag=True) is False

    def test_env_none_without_cli_disable_returns_true(self):
        assert resolve_dns_protection_enabled(None, cli_disable_flag=False) is True

    def test_unrecognized_env_falls_back_to_cli_flag(self):
        assert resolve_dns_protection_enabled("maybe", cli_disable_flag=True) is False

    def test_whitespace_trimmed(self):
        assert resolve_dns_protection_enabled("  false  ", cli_disable_flag=False) is False

    @pytest.mark.parametrize("value", ["", "  ", "\t"])
    def test_empty_or_whitespace_treated_as_unset(self, value: str):
        assert resolve_dns_protection_enabled(value, cli_disable_flag=False) is True
        assert resolve_dns_protection_enabled(value, cli_disable_flag=True) is False


class TestParseCommaSeparated:
    def test_comma_separated_values(self):
        assert parse_comma_separated("host1,host2,host3") == ["host1", "host2", "host3"]

    def test_whitespace_trimmed(self):
        assert parse_comma_separated(" host1 , host2 , host3 ") == ["host1", "host2", "host3"]

    def test_empty_entries_filtered(self):
        assert parse_comma_separated("host1,,host2,") == ["host1", "host2"]

    def test_all_empty_entries_returns_none(self):
        assert parse_comma_separated(",,") is None

    def test_empty_string_returns_none(self):
        assert parse_comma_separated("") is None

    def test_first_non_none_wins(self):
        assert parse_comma_separated("env-host", "cli-host") == ["env-host"]

    def test_skips_none_to_fallback(self):
        assert parse_comma_separated(None, "cli-host:*") == ["cli-host:*"]

    def test_all_none_returns_none(self):
        assert parse_comma_separated(None, None) is None

    def test_single_value(self):
        assert parse_comma_separated("localhost:*") == ["localhost:*"]

    def test_whitespace_only_entries_filtered(self):
        assert parse_comma_separated("host1, , ,host2") == ["host1", "host2"]


class TestTransportSecurityIntegration:
    @pytest.fixture(autouse=True)
    def _preserve_mcp_state(self):
        from postgres_mcp.server import mcp

        original_argv = sys.argv
        original_security = mcp.settings.transport_security
        yield
        sys.argv = original_argv
        mcp.settings.transport_security = original_security

    @pytest.mark.asyncio
    async def test_disable_dns_rebinding_via_cli_flag(self):
        from postgres_mcp.server import main
        from postgres_mcp.server import mcp

        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--transport=sse",
            "--disable-dns-rebinding-protection",
        ]

        with (
            patch("postgres_mcp.server.db_connection.pool_connect", AsyncMock()),
            patch("postgres_mcp.server.mcp.run_sse_async", AsyncMock()),
        ):
            await main()
            assert mcp.settings.transport_security is not None
            assert mcp.settings.transport_security.enable_dns_rebinding_protection is False

    @pytest.mark.asyncio
    async def test_env_var_overrides_cli_disable_flag(self):
        from postgres_mcp.server import main
        from postgres_mcp.server import mcp

        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--transport=sse",
            "--disable-dns-rebinding-protection",
        ]

        with (
            patch("postgres_mcp.server.db_connection.pool_connect", AsyncMock()),
            patch("postgres_mcp.server.mcp.run_sse_async", AsyncMock()),
            patch.dict("os.environ", {"POSTGRES_MCP_DNS_REBINDING_PROTECTION": "true"}),
        ):
            await main()
            assert mcp.settings.transport_security is not None
            assert mcp.settings.transport_security.enable_dns_rebinding_protection is True

    @pytest.mark.asyncio
    async def test_allowed_hosts_via_cli(self):
        from postgres_mcp.server import main
        from postgres_mcp.server import mcp

        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--transport=sse",
            "--allowed-hosts",
            "localhost:*,127.0.0.1:*",
        ]

        with (
            patch("postgres_mcp.server.db_connection.pool_connect", AsyncMock()),
            patch("postgres_mcp.server.mcp.run_sse_async", AsyncMock()),
        ):
            await main()
            assert mcp.settings.transport_security is not None
            assert mcp.settings.transport_security.enable_dns_rebinding_protection is True
            assert "localhost:*" in mcp.settings.transport_security.allowed_hosts
            assert "127.0.0.1:*" in mcp.settings.transport_security.allowed_hosts

    @pytest.mark.asyncio
    async def test_allowed_hosts_env_overrides_cli(self):
        from postgres_mcp.server import main
        from postgres_mcp.server import mcp

        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--transport=sse",
            "--allowed-hosts",
            "cli-host:*",
        ]

        with (
            patch("postgres_mcp.server.db_connection.pool_connect", AsyncMock()),
            patch("postgres_mcp.server.mcp.run_sse_async", AsyncMock()),
            patch.dict("os.environ", {"POSTGRES_MCP_ALLOWED_HOSTS": "env-host:*"}),
        ):
            await main()
            assert mcp.settings.transport_security is not None
            assert "env-host:*" in mcp.settings.transport_security.allowed_hosts
            assert "cli-host:*" not in mcp.settings.transport_security.allowed_hosts

    @pytest.mark.asyncio
    async def test_default_dns_protection_active(self):
        from postgres_mcp.server import main
        from postgres_mcp.server import mcp

        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--transport=sse",
        ]

        with (
            patch("postgres_mcp.server.db_connection.pool_connect", AsyncMock()),
            patch("postgres_mcp.server.mcp.run_sse_async", AsyncMock()),
        ):
            await main()
            assert mcp.settings.transport_security is not None
            assert mcp.settings.transport_security.enable_dns_rebinding_protection is True

    @pytest.mark.asyncio
    async def test_only_allowed_origins_without_hosts(self):
        from postgres_mcp.server import main
        from postgres_mcp.server import mcp

        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--transport=sse",
            "--allowed-origins",
            "http://localhost:*",
        ]

        with (
            patch("postgres_mcp.server.db_connection.pool_connect", AsyncMock()),
            patch("postgres_mcp.server.mcp.run_sse_async", AsyncMock()),
        ):
            await main()
            assert mcp.settings.transport_security is not None
            assert mcp.settings.transport_security.enable_dns_rebinding_protection is True
            assert "http://localhost:*" in mcp.settings.transport_security.allowed_origins

    @pytest.mark.asyncio
    async def test_disable_flag_ignores_allowed_hosts_with_warning(self, caplog):
        from postgres_mcp.server import main
        from postgres_mcp.server import mcp

        sys.argv = [
            "postgres_mcp",
            "postgresql://user:password@localhost/db",
            "--transport=sse",
            "--disable-dns-rebinding-protection",
            "--allowed-hosts",
            "localhost:*",
        ]

        with (
            caplog.at_level(logging.WARNING, logger="postgres_mcp.server"),
            patch("postgres_mcp.server.db_connection.pool_connect", AsyncMock()),
            patch("postgres_mcp.server.mcp.run_sse_async", AsyncMock()),
        ):
            await main()
            assert mcp.settings.transport_security is not None
            assert mcp.settings.transport_security.enable_dns_rebinding_protection is False
            assert "--allowed-hosts/--allowed-origins ignored" in caplog.text

    @pytest.mark.asyncio
    async def test_database_url_after_allowed_hosts_not_consumed(self):
        from postgres_mcp.server import main
        from postgres_mcp.server import mcp

        sys.argv = [
            "postgres_mcp",
            "--transport=sse",
            "--allowed-hosts",
            "localhost:*,my-gateway:8080",
            "--allowed-origins",
            "http://localhost:*,http://my-gateway:*",
            "postgresql://user:password@localhost/db",
        ]

        with (
            patch("postgres_mcp.server.db_connection.pool_connect", AsyncMock()),
            patch("postgres_mcp.server.mcp.run_sse_async", AsyncMock()),
        ):
            await main()
            assert mcp.settings.transport_security is not None
            assert "localhost:*" in mcp.settings.transport_security.allowed_hosts
            assert "my-gateway:8080" in mcp.settings.transport_security.allowed_hosts
