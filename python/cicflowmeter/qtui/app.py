"""Entry point wiring the Qt application to the main window."""

from __future__ import annotations

import argparse
import logging
import sys

try:
    from PySide6.QtWidgets import QApplication
except ImportError as exc:  # pragma: no cover - executed only when dependency missing
    raise SystemExit(
        "PySide6 is required for the GUI. Install with `pip install cicflowmeter[gui]`."
    ) from exc

from .main_window import MainWindow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launch the CICFlowMeter Qt operator console.")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Python logging level for diagnostics.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level))

    app = QApplication.instance()
    if app is None:
        qt_args = sys.argv if argv is None else [sys.argv[0]]
        app = QApplication(qt_args)

    app.setApplicationName("CICFlowMeter GUI")
    window = MainWindow()
    window.show()

    return app.exec()


__all__ = ["main"]
