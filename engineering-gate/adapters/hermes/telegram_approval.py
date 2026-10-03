"""Gate-owned Telegram DM approval broker; distinct from Hermes ea:* approvals."""
import re


def register_telegram_approval_observer(ctx, service):
    """Register the Gate-only ``eg1:`` nonce callback handler."""
    service.register_telegram_handler(ctx)


__all__ = ["register_telegram_approval_observer"]
