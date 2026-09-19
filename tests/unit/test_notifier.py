from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from deceptenv.config import SecurityConfig
from deceptenv.engine.forensics import ForensicReport, ProcessInfo
from deceptenv.engine.notifier import SlackNotifier


@pytest.mark.asyncio
async def test_slack_notifier_no_url(tmp_path: Path) -> None:
    config = SecurityConfig(canary_directory=tmp_path, slack_webhook_url=None)
    notifier = SlackNotifier(config)

    report = ForensicReport(
        lineage=[ProcessInfo(pid=1234, ppid=1, name="malware", cmdline=["./malware"])]
    )

    # Should safely return without sending
    await notifier.notify_incident(report, 1234, tmp_path / "credentials.honey")


@pytest.mark.asyncio
async def test_slack_notifier_success(tmp_path: Path) -> None:
    config = SecurityConfig(
        canary_directory=tmp_path,
        slack_webhook_url="https://hooks.slack.com/services/test/test/test",
    )
    notifier = SlackNotifier(config)

    report = ForensicReport(
        lineage=[ProcessInfo(pid=1234, ppid=1, name="malware", cmdline=["./malware"])]
    )

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        await notifier.notify_incident(report, 1234, tmp_path / "credentials.honey")
        assert mock_urlopen.called


@pytest.mark.asyncio
async def test_slack_notifier_error_handled(tmp_path: Path) -> None:
    config = SecurityConfig(
        canary_directory=tmp_path,
        slack_webhook_url="https://hooks.slack.com/services/test/test/test",
    )
    notifier = SlackNotifier(config)

    report = ForensicReport()

    with patch("urllib.request.urlopen", side_effect=OSError("Network unreachable")):
        # Should not raise exception
        await notifier.notify_incident(report, 1234, tmp_path / "credentials.honey")
