# time_utils.py
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

UTC = timezone.utc
IST = ZoneInfo("Asia/Kolkata")

def now_utc():
    return datetime.now(UTC).replace(tzinfo=None)

def utc_to_ist(dt: datetime):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(IST)
