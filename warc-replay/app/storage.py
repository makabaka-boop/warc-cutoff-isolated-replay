"""In-memory archive store.

The task constrains a single import to *at most* ten records totalling
64 KiB of uncompressed payload, so a process-wide in-memory store with a
single lock is sufficient.  Records are never persisted and never fetched
from anywhere: the replay service only ever serves what is in here.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Optional

# Hard limits demanded by the specification.
MAX_RECORDS = 10
MAX_TOTAL_BYTES = 64 * 1024  # uncompressed HTTP payload only

UTF8 = "utf-8"
HTML = "text/html;charset=utf-8"
PNG = "image/png"


class StoreError(Exception):
    """Store-level rejection (quota / duplicate)."""

    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


class Record:
    __slots__ = ("record_id", "uri", "date", "content_type", "body", "length")

    def __init__(
        self,
        record_id: str,
        uri: str,
        date: datetime,
        content_type: str,
        body: bytes,
    ):
        self.record_id = record_id
        self.uri = uri
        self.date = date.astimezone(timezone.utc)
        self.content_type = content_type
        self.body = body
        self.length = len(body)

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "uri": self.uri,
            "date": self.date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "content_type": self.content_type,
            "length": self.length,
        }


class ArchiveStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: list[Record] = []
        self._ids: set[str] = set()
        # (uri, date) pairs are unique -- same URI captured at the same
        # instant more than once is an explicit rejection.
        self._uri_dates: set[tuple[str, datetime]] = set()

    def reset(self) -> None:
        with self._lock:
            self._records.clear()
            self._ids.clear()
            self._uri_dates.clear()

    def stats(self) -> dict:
        with self._lock:
            return {
                "records": len(self._records),
                "max_records": MAX_RECORDS,
                "total_bytes": sum(r.length for r in self._records),
                "max_total_bytes": MAX_TOTAL_BYTES,
            }

    def list_records(self) -> list[Record]:
        with self._lock:
            return sorted(self._records, key=lambda r: (r.uri, r.date))

    def add_batch(self, records: list[Record]) -> None:
        """Add a validated import batch atomically (all-or-nothing)."""
        with self._lock:
            batch_ids = {r.record_id for r in records}
            batch_uri_dates = {(r.uri, r.date) for r in records}

            if len(batch_ids) != len(records):
                raise StoreError("duplicate WARC-Record-ID inside the import")
            if len(batch_uri_dates) != len(records):
                raise StoreError(
                    "same URI captured at the same timestamp more than once"
                )
            if self._ids & batch_ids:
                raise StoreError("WARC-Record-ID already present in archive")
            if self._uri_dates & batch_uri_dates:
                raise StoreError(
                    "an identical URI/date capture already exists in the archive"
                )
            if len(self._records) + len(records) > MAX_RECORDS:
                raise StoreError(
                    f"archive holds at most {MAX_RECORDS} records", status=413
                )
            extra = sum(r.length for r in records)
            if sum(r.length for r in self._records) + extra > MAX_TOTAL_BYTES:
                raise StoreError(
                    f"total payload exceeds {MAX_TOTAL_BYTES} bytes", status=413
                )

            self._records.extend(records)
            self._ids.update(batch_ids)
            self._uri_dates.update(batch_uri_dates)

    def select(self, uri: str, cutoff: datetime) -> Optional[Record]:
        """Latest record for *uri* captured no later than *cutoff*.

        Same-URI/same-date duplicates can never exist here (rejected at
        import), so the latest-at-or-before capture is unambiguous.
        """
        cutoff = cutoff.astimezone(timezone.utc)
        with self._lock:
            candidates = [
                r for r in self._records if r.uri == uri and r.date <= cutoff
            ]
            if not candidates:
                return None
            return max(candidates, key=lambda r: r.date)


store = ArchiveStore()
