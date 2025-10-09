# cicflowmeter

Python translation of the CICFlowMeter core flow parsing components.

## Installation

Install from the project root with the optional extra for live capture support:

```bash
pip install .[live]
```

When using Poetry, enable the extras via:

```bash
poetry install -E live
```

## Usage

### Batch CLI

Generate flow CSVs from PCAP files using the CLI:

```bash
cicflowmeter /path/to/pcaps output_dir
```

Use `--ip-summary` to emit per-endpoint aggregates and `--time-buckets <seconds>` to roll flows into fixed time windows alongside the primary `_Flow.csv` outputs.

See `cicflowmeter --help` for the full set of flow timeout, protocol, and logging options.

Ensure the `live` extra (Scapy) is installed to enable live packet capture.
