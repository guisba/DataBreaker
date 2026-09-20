from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from ..models import CleanMode, Finding, NormalizationProfile


class FormatHandler(ABC):
    formats: tuple[str, ...] = ()

    @abstractmethod
    def scan(self, path: Path) -> tuple[list[Finding], list[str], str | None]: ...

    @abstractmethod
    def clean(self, source: Path, destination: Path, mode: CleanMode, profile: NormalizationProfile, options: dict[str, bool] | None = None) -> list[str]: ...

    @abstractmethod
    def validate(self, path: Path) -> tuple[bool, str]: ...

    def supports_cleaning(self) -> bool:
        return True


def iter_handlers(handlers: Iterable[FormatHandler], fmt: str) -> FormatHandler | None:
    return next((handler for handler in handlers if fmt in handler.formats), None)
