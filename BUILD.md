# Build and Run Guide

This project ships both Maven and Gradle build files. Maven is the preferred workflow, but the Gradle wrapper remains available if you need it.

## Prerequisites
- Java Development Kit 8 (Temurin or OpenJDK). On macOS install via `brew install --cask temurin@8` and export it with `export JAVA_HOME=$(/usr/libexec/java_home -v1.8)`.
- Apache Maven 3.6+ (install via `brew install maven` on macOS or your preferred package manager).
- A native packet capture library that matches your platform (e.g., libpcap on macOS) so `jnetpcap` can access network devices.

> **Note:** The repository no longer ships Linux or Windows native binaries. Supply a platform-appropriate build of `jnetpcap` (jar + native library) and point the tooling at it as described below.

## One-time setup: install the JNetPcap jar
Both Maven and Gradle resolve `org.jnetpcap:jnetpcap:1.4.1` from your local Maven cache. Seed it once per machine using the jar you obtained for your platform:

```bash
mvn install:install-file \
  -Dfile=/path/to/jnetpcap.jar \
  -DgroupId=org.jnetpcap \
  -DartifactId=jnetpcap \
  -Dversion=1.4.1 \
  -Dpackaging=jar
```
> Use the matching jar path for your environment.

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
  -Djava.library.path=/path/to/native/lib/dir \
  -jar target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar
```

Set `-Djava.library.path` to the directory that contains your native `jnetpcap` library (for example, the folder holding `libjnetpcap.dylib` on macOS).

### Command-line mode
```bash
sudo java \
  -Djava.library.path=/path/to/native/lib/dir \
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
./gradlew execute -PjnetpcapNativePath=/path/to/native/lib/dir
./gradlew exeCMD -PjnetpcapNativePath=/path/to/native/lib/dir --args="/pcap/in /csv/out"
./gradlew distZip         # create build/distributions/CICFlowMeter-*.zip
```

Alternatively, export `JNETPCAP_NATIVE_PATH=/path/to/native/lib/dir` and the Gradle tasks will pick it up automatically.

## Troubleshooting
- `UnsupportedClassVersionError`: Verify `java -version` reports 1.8.
- `UnsatisfiedLinkError` for `jnetpcap`: Ensure the jar is installed locally, and that `java.library.path` (or `JNETPCAP_NATIVE_PATH`) targets the folder containing your native library for the current platform/architecture.
- Permission denied opening devices: rerun with `sudo` (macOS) or the appropriate elevated context for your OS.
