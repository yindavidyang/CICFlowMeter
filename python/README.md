# cicflowmeter

Python translation of the CICFlowMeter core flow parsing components.

## Installation

Install from the project root with the optional extras for live capture and the Qt UI:

```bash
pip install .[live,gui]
```

When using Poetry, enable the extras via:

```bash
poetry install -E live -E gui
```

## Usage

### Batch CLI

Generate flow CSVs from PCAP files using the CLI:

```bash
cicflowmeter /path/to/pcaps output_dir
```

Use `--ip-summary` to emit per-endpoint aggregates and `--time-buckets <seconds>` to roll flows into fixed time windows alongside the primary `_Flow.csv` outputs.

See `cicflowmeter --help` for the full set of flow timeout, protocol, and logging options.

### Qt Operator Console

Launch the PySide-based operator console for live capture monitoring:

```bash
cicflowmeter-gui
```

The GUI exposes:

- Interface selection with optional BPF filters.
- Start/stop controls for the Scapy-powered live capture pipeline.
- A rolling table of recently completed flows with per-flow metadata.
- Inline status logs for capture state transitions and errors.
- A live flow-rate chart summarizing recent capture throughput.
- Live analytics charts with selectable metrics, color-coded clustering, PCA projections, optional 3D scatter, and continuously refreshed histograms/scatter plots.
- Batch processing tools with cancellation controls, quick output previews, saved presets, rerun shortcuts, and a persisted list of recent CSV artifacts.

Ensure the `live` extra (Scapy) is installed to enable live packet capture.
