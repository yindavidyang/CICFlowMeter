## Install jnetpcap locally

Seed the `jnetpcap` jar into your local Maven cache using the artifact that matches your platform:

```bash
mvn install:install-file \
  -Dfile=/path/to/jnetpcap.jar \
  -DgroupId=org.jnetpcap \
  -DartifactId=jnetpcap \
  -Dversion=1.4.1 \
  -Dpackaging=jar
```

## Run

### IntelliJ IDEA

Open a terminal inside the IDE:

```bash
export JNETPCAP_NATIVE_PATH=/path/to/native/lib/dir   # contains your libjnetpcap.*
./gradlew execute
```

Elevated privileges may still be required to access capture devices (`sudo` on macOS).

### Eclipse

1. Right click `App.java` → Run As → Run Configurations → Arguments → VM arguments:  
   `-Djava.library.path=/path/to/native/lib/dir`
2. Run the configuration.

## Build packages

### IntelliJ IDEA / Gradle

```bash
./gradlew distZip
```

The archive is created under `CICFlowMeter/build/distributions`.

### Eclipse / Maven

```bash
mvn package
```

The jar is produced in `CICFlowMeter/target`.
