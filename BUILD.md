# Build and Run Guide

This project ships both Maven and Gradle build files. Maven is the preferred workflow, but the Gradle wrapper remains available if you need it.

## Prerequisites
- Java Development Kit 8 (Temurin or OpenJDK). On macOS install via `brew install --cask temurin@8` and export it with `export JAVA_HOME=$(/usr/libexec/java_home -v1.8)`.
- Apache Maven 3.6+ (`brew install maven` on macOS, `sudo apt-get install maven` on Debian/Ubuntu, `choco install maven` on Windows).
- Native packet capture library (libpcap on Unix, WinPcap/Npcap on Windows) for live capture features.

> **Note:** The repo bundles native `jnetpcap` binaries for Linux (`.so`) and Windows (`.dll`). macOS users need either a Linux environment (VM/container) or a macOS build of `jnetpcap` before GUI/CLI capture will work.

## One-time setup: install the JNetPcap jar
Both Maven and Gradle resolve `org.jnetpcap:jnetpcap:1.4.1` from your local Maven cache. Seed it once per machine:

```bash
mvn install:install-file \
  -Dfile=jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar \
  -DgroupId=org.jnetpcap \
  -DartifactId=jnetpcap \
  -Dversion=1.4.1 \
  -Dpackaging=jar
```

Repeat with the Windows jar if you also build there (`jnetpcap/win/jnetpcap-1.4.r1425/jnetpcap.jar`).

## Build with Maven (preferred)
```bash
mvn clean package
```

Artifacts:
- Fat jar with all dependencies: `target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar`
- Temporary build outputs under `target/`

## Run the application
Running usually requires elevated privileges so the JVM can access capture devices.

### GUI mode
```bash
sudo java \
  -Djava.library.path=jnetpcap/linux/jnetpcap-1.4.r1425 \
  -jar target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar
```
On Windows replace the library path with `jnetpcap/win/jnetpcap-1.4.r1425` and drop `sudo`.

### Command-line mode
```bash
sudo java \
  -Djava.library.path=jnetpcap/linux/jnetpcap-1.4.r1425 \
  -cp target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar \
  cic.cs.unb.ca.ifm.Cmd \
  /path/to/pcap/dir \
  /path/to/output/dir
```
The CLI processes all pcaps in the input folder and writes CSVs to the output folder.

## Optional: Gradle wrapper tasks
If you prefer Gradle or need the distribution zip, the wrapper is already included.

```bash
./gradlew build           # compile & test
./gradlew execute         # launch the GUI (uses the same native lib path logic)
./gradlew exeCMD --args="/pcap/in /csv/out"  # headless CLI
./gradlew distZip         # create build/distributions/CICFlowMeter-*.zip
```

## Troubleshooting
- `UnsupportedClassVersionError`: Verify `java -version` reports 1.8.
- `UnsatisfiedLinkError` for `jnetpcap`: Ensure `java.library.path` points at the matching OS folder under `jnetpcap/` and that the native library matches your platform/architecture.
- Permission denied opening devices: rerun with `sudo` (Linux/macOS) or launch an elevated shell (Windows).
