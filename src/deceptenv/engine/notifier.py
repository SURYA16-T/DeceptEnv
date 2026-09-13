import asyncio
import json
import logging
import urllib.request
from pathlib import Path
from typing import Any, Optional

from deceptenv.config import SecurityConfig
from deceptenv.engine.forensics import ForensicReport

logger = logging.getLogger(__name__)

class SlackNotifier:
    def __init__(self, config: SecurityConfig) -> None:
        self.webhook_url: Optional[str] = config.slack_webhook_url

    def _sync_post(self, payload: dict[str, Any]) -> None:
        if not self.webhook_url:
            return

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status not in (200, 201, 204):
                    logger.error(f"Slack webhook failed with status {response.status}")
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")

    async def notify_incident(self, report: ForensicReport, pid: int, tripwire: Path) -> None:
        """
        Construct a Slack Block Kit payload and dispatch it in a separate thread.
        """
        if not self.webhook_url:
            return

        import os
        uid = os.getuid() if hasattr(os, "getuid") else "N/A"
        binary_path = report.lineage[0].name if report.lineage else "Unknown"
        cmdline: list[str] = report.lineage[0].cmdline if report.lineage else []
        cmdline_str = " ".join(cmdline) if cmdline else "Unknown"

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 DeceptEnv Incident Mitigated",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Offending PID:*\n{pid}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*User UID:*\n{uid}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Binary Path:*\n`{binary_path}`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Tripwire:*\n`{tripwire}`"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Command Line:*\n```{cmdline_str}```"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Mitigation Status:*\n`SUSPEND` -> *FROZEN*"
                    }
                }
            ]
        }

        # Dispatch off the main async loop
        await asyncio.to_thread(self._sync_post, payload)
