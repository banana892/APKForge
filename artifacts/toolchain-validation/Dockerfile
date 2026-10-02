FROM eclipse-temurin:17-jdk-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    libstdc++6 \
    zlib1g \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install pinned Apktool 2.10.0
RUN mkdir -p /opt/apktool
COPY apktool.jar /opt/apktool/apktool.jar
RUN printf '#!/bin/bash\nexec java -jar /opt/apktool/apktool.jar "$@"\n' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool

# Install pinned Android Build Tools 34.0.0
# Source: https://dl.google.com/android/repository/build-tools_r34-linux.zip
# SHA-256: e858c4b60069d0431051b225d384413b1643e1289b00a4825aed347f25bd510f
ENV ANDROID_BUILD_TOOLS_VERSION=34.0.0
ENV BUILD_TOOLS_SHA256="e858c4b60069d0431051b225d384413b1643e1289b00a4825aed347f25bd510f"
RUN mkdir -p /opt/android-sdk/build-tools \
    && curl -fsSL -o /tmp/build-tools.zip https://dl.google.com/android/repository/build-tools_r34-linux.zip \
    && echo "${BUILD_TOOLS_SHA256}  /tmp/build-tools.zip" | sha256sum -c - \
    && unzip -q /tmp/build-tools.zip -d /tmp/build-tools-extracted \
    && mv /tmp/build-tools-extracted/android-14 /opt/android-sdk/build-tools/34.0.0 \
    && rm -rf /tmp/build-tools.zip /tmp/build-tools-extracted \
    && chmod -R a+rX /opt/android-sdk/build-tools/34.0.0

ENV PATH="/opt/android-sdk/build-tools/34.0.0:${PATH}"

WORKDIR /workspace
