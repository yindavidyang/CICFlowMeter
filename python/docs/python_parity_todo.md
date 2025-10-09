# Python Port Parity TODO

The Python package currently covers only the core flow data structures and metrics. The following work remains to reach feature parity with the Java CICFlowMeter toolchain.

- **PCAP ingestion layer** *(done)*: implemented as `cicflowmeter.packet_reader.PacketReader`, covering IPv4/IPv6 TCP/UDP decoding and timestamp tracking.
- **Batch CLI pipeline** *(done)*: use `cicflowmeter.cli:main` (exposed via the `cicflowmeter` console script) to enumerate PCAP files, run the flow generator, and emit CSV flow reports.
- **Real-time capture & listeners** *(done)*: implemented as `cicflowmeter.live_capture.LiveCapture`, which wraps a Scapy `AsyncSniffer` and forwards packets through the `FlowGenerator` listener API.
- **GUI / operator tooling** *(out of scope)*: the current Python package is headless and intentionally limited to CLI workflows. Matching the legacy Swing UI would require building a new desktop console or porting the Java UI, neither of which is planned.
- **Visualization & clustering** *(in progress)*: the `cicflowmeter.clustering` module mirrors the Java `WekaFactory`/`WekaXMeans` responsibilities (CSV ingestion with missing-value handling, PCA-based projections, automatic k-means cluster selection) and now exposes cluster summaries for downstream dashboards. Remaining work involves wiring these building blocks into dedicated reporting surfaces and multi-metric charting comparable to the legacy Weka visualizations.
- **Ancillary utilities** *(done)*: implemented in `cicflowmeter.ancillary` with incremental CSV writing plus helpers for IP endpoint summaries and time-bucket aggregation exposed through `FlowGenerator`.

Documenting these gaps early should help guide scope decisions (e.g., whether to keep the Python port headless or to match the full Java UX).
