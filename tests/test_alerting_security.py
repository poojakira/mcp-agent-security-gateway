"""Security regression tests for webhook alert transport and log redaction."""

from unittest.mock import patch

from mcp_monitor.production.alerting import AlertingHook


def test_non_loopback_plain_http_webhook_is_rejected():
    hook = AlertingHook(webhook_url="http://alerts.example.com/secret-token")
    with patch("mcp_monitor.production.alerting.urllib.request.urlopen") as urlopen:
        hook._send_webhook({"text": "test"})
    urlopen.assert_not_called()


def test_webhook_failure_log_does_not_include_secret_url():
    secret_url = "https://hooks.example.com/services/secret-token-value"
    hook = AlertingHook(webhook_url=secret_url)

    with (
        patch(
            "mcp_monitor.production.alerting.urllib.request.urlopen",
            side_effect=OSError("delivery failed"),
        ),
        patch("mcp_monitor.production.alerting._logger.warning") as warning,
    ):
        hook._send_webhook({"text": "test"})

    rendered = repr(warning.call_args)
    assert secret_url not in rendered
    assert "secret-token-value" not in rendered
    assert "hooks.example.com" in rendered
