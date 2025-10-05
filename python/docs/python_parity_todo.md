# Python Port Parity TODO

The Python package currently covers only the core flow data structures and metrics. The following work remains to reach feature parity with the Java CICFlowMeter toolchain.

- **PCAP ingestion layer** *(done)*: implemented as `cicflowmeter.packet_reader.PacketReader`, covering IPv4/IPv6 TCP/UDP decoding and timestamp tracking.
- **Batch CLI pipeline** *(done)*: use `cicflowmeter.cli:main` (exposed via the `cicflowmeter` console script) to enumerate PCAP files, run the flow generator, and emit CSV flow reports.
- **Real-time capture & listeners** *(done)*: implemented as `cicflowmeter.live_capture.LiveCapture`, which wraps a Scapy `AsyncSniffer` and forwards packets through the `FlowGenerator` listener API.
- **GUI / operator tooling**: if parity with the desktop application is desired, design a replacement for the Swing UI (offline batch controls, real-time monitor, visualization panes) found under `src/main/java/cic/cs/unb/ca/flow/ui` and `swing/common`.
- **Visualization & clustering**: translate the Weka-based clustering/dimensionality-reduction pipeline (`src/main/java/cic/cs/unb/ca/weka`) to Python using libraries such as scikit-learn or seaborn/matplotlib, and integrate it with whichever UI or reporting surfaces replace the Java charts.
- **Ancillary utilities** *(done)*: implemented in `cicflowmeter.ancillary` with incremental CSV writing plus helpers for IP endpoint summaries and time-bucket aggregation exposed through `FlowGenerator`.

Documenting these gaps early should help guide scope decisions (e.g., whether to keep the Python port headless or to match the full Java UX).
