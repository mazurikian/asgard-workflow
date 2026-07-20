# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations


class FUSError(RuntimeError):
    pass


class RetryableDownloadError(FUSError):
    pass


class StreamSourceError(Exception):
    """A cached random-access stream could not be read reliably."""
