# Runs APKForge's ModKit discovery/detection (incl. the Morphe adapter) in a container.
# Java 21 here is the project's actual floor: MorpheAdapter.MIN_JAVA_MAJOR in
# src/apkforge/modkit/morphe/adapter.py pins it, and Morphe Desktop itself requires 21+.
# APKForge never bundles Morphe (GPL-3.0 + branding restrictions, see docs/modkits.md) —
# mount your own jar and a modkits.toml pointing [modkits.morphe].executable_path at it.
# Debian bookworm has no openjdk-21 package; eclipse-temurin's own Java 21 image
# ships Python 3.12 (Ubuntu noble) on top, so it covers both requirements.
FROM eclipse-temurin:21-jre-noble

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml LICENSE README.md ./
COPY src ./src
RUN pip3 install --no-cache-dir --break-system-packages .

ENTRYPOINT ["apkforge"]
CMD ["modkits"]
