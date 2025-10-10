import httpx
import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from models import WebhookLogs
from logger import logger
from database import get_db

db = next(get_db())


class WebhookService:
    async def send_webhook(
        self, user_id: int, scan_id: int, webhook_url: str, payload: Dict[str, Any]
    ) -> bool:
        """Send webhook notification for scan completion"""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(webhook_url, json=payload)

                # Log the webhook attempt
                webhook_log = WebhookLogs(
                    user_id=user_id,
                    scan_id=scan_id,
                    webhook_url=webhook_url,
                    status_code=response.status_code,
                    response=response.text,
                )

                self.db.add(webhook_log)
                self.db.commit()

                logger.info(
                    f"Webhook sent to {webhook_url} - Status: {response.status_code}"
                )
                return response.status_code == 200

        except Exception as e:
            # Log failed webhook attempt
            webhook_log = WebhookLogs(
                user_id=user_id,
                scan_id=scan_id,
                webhook_url=webhook_url,
                status_code=0,
                response=str(e),
            )

            self.db.add(webhook_log)
            self.db.commit()

            logger.error(f"Webhook failed for {webhook_url}: {e}")
            return False

    def get_webhook_logs(self, user_id: int, limit: int = 10):
        """Get webhook logs for a user"""
        return (
            self.db.query(WebhookLogs)
            .filter(WebhookLogs.user_id == user_id)
            .order_by(WebhookLogs.sent_at.desc())
            .limit(limit)
            .all()
        )
