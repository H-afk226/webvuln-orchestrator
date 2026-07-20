FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        sqlmap \
        whatweb \
        dnsutils \
        curl \
        git \
        bsdmainutils \
        procps \
        perl \
        libnet-ssleay-perl \
        libjson-perl \
        openssl \
        ca-certificates \
        bash \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

# Nikto — not packaged in Debian; installed from upstream, pinned for reproducibility
RUN git clone --depth 1 --branch 2.5.0 \
        https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# testssl.sh — pinned tag, not master, for reproducible results
RUN git clone --depth 1 --branch v3.2.4 \
        https://github.com/testssl/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir wapiti3 \
    && pip install --no-cache-dir --upgrade 'typing_extensions>=4.14'

COPY src/ ./src/
RUN mkdir -p /app/results /app/config

CMD ["sleep", "infinity"]
