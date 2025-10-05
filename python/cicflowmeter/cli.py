"""Command-line entry point for batch PCAP to flow CSV conversion."""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from .ancillary import IncrementalCSVWriter
from .flow_feature import FlowFeature
from .flow_generator import FlowGenerator
from .packet_reader import PacketReader
from .utils import FLOW_SUFFIX

logger = logging.getLogger(__name__)


@dataclass
class FlowStats:
    total_packets: int = 0
    valid_packets: int = 0
    flows_written: int = 0


class CSVFlowWriter:
    """Writes generated flows to disk as CSV rows."""

    def __init__(self, output_file: Path, header: str) -> None:
        self._writer = IncrementalCSVWriter(output_file, header)
        self.flows_written = 0

    def on_flow_generated(self, flow) -> None:  # type: ignore[override]
        if flow.packet_count() <= 1:
            return
        self.flows_written += self._writer.append_rows(
            [flow.dump_flow_based_features_ex()]
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate CICFlowMeter CSV flow features from PCAP captures.",
    )
    parser.add_argument(
        "pcap_path",
        type=Path,
        help="Path to a PCAP file or a directory containing PCAP files.",
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="Directory where generated *_Flow.csv files will be written.",
    )
    parser.add_argument(
        "--flow-timeout",
        type=float,
        default=120.0,
        metavar="SECONDS",
        help="Flow timeout in seconds (default: 120).",
    )
    parser.add_argument(
        "--activity-timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="Flow activity timeout in seconds (default: 5).",
    )
    parser.add_argument(
        "--ipv6",
        action="store_true",
        help="Enable IPv6 packet parsing (disabled by default).",
    )
    parser.add_argument(
        "--no-ipv4",
        action="store_true",
        help="Disable IPv4 packet parsing (enabled by default).",
    )
    parser.add_argument(
        "--unidirectional",
        action="store_true",
        help="Generate unidirectional flows (default is bidirectional).",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Log level for diagnostic output.",
    )
    return parser


def collect_pcaps(path: Path) -> List[Path]:
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise FileNotFoundError(f"PCAP path is neither file nor directory: {path}")

    candidates: Iterable[Path] = path.iterdir()
    pcaps = [
        entry
        for entry in sorted(candidates)
        if entry.is_file() and entry.suffix.lower() in {".pcap", ".pcapng"}
    ]
    return pcaps


def process_pcap(
    pcap_file: Path,
    output_dir: Path,
    *,
    bidirectional: bool,
    flow_timeout_s: float,
    activity_timeout_s: float,
    read_ip4: bool,
    read_ip6: bool,
) -> FlowStats:
    stats = FlowStats()

    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{pcap_file.name}{FLOW_SUFFIX}"
    if output_file.exists():
        output_file.unlink()

    header = FlowFeature.get_header()
    writer = CSVFlowWriter(output_file, header)

    flow_generator = FlowGenerator(
        bidirectional=bidirectional,
        flow_timeout=int(flow_timeout_s * 1_000_000),
        activity_timeout=int(activity_timeout_s * 1_000_000),
    )
    flow_generator.add_flow_listener(writer)

    with PacketReader(pcap_file, read_ip4=read_ip4, read_ip6=read_ip6) as reader:
        while True:
            packet = reader.next_packet()
            if packet is None:
                break
            stats.total_packets += 1
            stats.valid_packets += 1
            flow_generator.add_packet(packet)

    stats.flows_written = writer.flows_written
    stats.flows_written += flow_generator.dump_labeled_current_flow(
        str(output_file),
        header,
    )

    return stats


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level))

    if args.no_ipv4 and not args.ipv6:
        parser.error("At least one of IPv4 or IPv6 processing must be enabled.")

    read_ip4 = not args.no_ipv4
    read_ip6 = args.ipv6

    try:
        pcaps = collect_pcaps(args.pcap_path)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return 1

    if not pcaps:
        logger.warning("No PCAP files found at %s", args.pcap_path)
        return 1

    exit_code = 0
    for index, pcap_file in enumerate(pcaps, 1):
        logger.info("Processing %s (%d/%d)", pcap_file, index, len(pcaps))
        try:
            stats = process_pcap(
                pcap_file,
                args.output_dir,
                bidirectional=not args.unidirectional,
                flow_timeout_s=args.flow_timeout,
                activity_timeout_s=args.activity_timeout,
                read_ip4=read_ip4,
                read_ip6=read_ip6,
            )
        except Exception as exc:  # pragma: no cover - unexpected runtime failures
            logger.exception("Failed processing %s", pcap_file)
            exit_code = 1
            continue

        logger.info(
            "Finished %s: packets=%d, flows=%d",
            pcap_file.name,
            stats.valid_packets,
            stats.flows_written,
        )

    return exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
