# Python Port Parity TODO

The Python package currently covers only the core flow data structures and metrics. The following work remains to reach feature parity with the Java CICFlowMeter toolchain.

- **PCAP ingestion layer** *(done)*: implemented as `cicflowmeter.packet_reader.PacketReader`, covering IPv4/IPv6 TCP/UDP decoding and timestamp tracking.
- **Batch CLI pipeline** *(done)*: use `cicflowmeter.cli:main` (exposed via the `cicflowmeter` console script) to enumerate PCAP files, run the flow generator, and emit CSV flow reports.
- **Real-time capture & listeners** *(done)*: implemented as `cicflowmeter.live_capture.LiveCapture`, which wraps a Scapy `AsyncSniffer` and forwards packets through the `FlowGenerator` listener API.
- **GUI / operator tooling** *(in progress)*: the PySide6 operator console (`cicflowmeter-gui`) now offers live-capture controls, a rolling flow table, configurable analytics (metric selection, PCA projection, color-coded clustering, optional 3D scatter), cluster drill-down/export, and batch PCAP → CSV orchestration with cancellation, saved presets, inline CSV previews, rerun shortcuts, and recent artifact access. Remaining work to match the Swing UI includes richer clustering visualizations (e.g., multi-metric drill-ins, anomaly alerts, streaming dashboards) and advanced alerting widgets located in `src/main/java/cic/cs/unb/ca/flow/ui` and `swing/common`.
- **Visualization & clustering**: translate the Weka-based clustering/dimensionality-reduction pipeline (`src/main/java/cic/cs/unb/ca/weka`) to Python using libraries such as scikit-learn or seaborn/matplotlib, and integrate it with whichever UI or reporting surfaces replace the Java charts.
- **Ancillary utilities** *(done)*: implemented in `cicflowmeter.ancillary` with incremental CSV writing plus helpers for IP endpoint summaries and time-bucket aggregation exposed through `FlowGenerator`.

Documenting these gaps early should help guide scope decisions (e.g., whether to keep the Python port headless or to match the full Java UX).
