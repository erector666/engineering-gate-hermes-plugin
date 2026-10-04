"""Strict extraction of Telegram requester identity from host event evidence."""


def telegram_requester_id(event):
    """Return a positive Telegram numeric user id; reject non-private or ambiguous inputs."""
    if not isinstance(event, dict):
        return None
    chat_type = event.get("chat_type")
    if chat_type is None or str(chat_type).lower() != "private":
        return None
    chat = event.get("chat")
    if isinstance(chat, dict) and str(chat.get("type", "")).lower() != "private":
        return None
    user = event.get("from_user")
    # Telegram's host Message.from_user.id is an integer. Serialized strings and
    # sender_id aliases are not proven by the pinned hook payload, so reject them.
    raw = user.get("id") if isinstance(user, dict) else None
    return raw if type(raw) is int and raw > 0 else None
