# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Non-root CLI image

FROM python:3.14-slim@sha256:d3400aa122fa42cf0af0dbe8ec3091b047eac5c8f7e3539f7135e86d855dc015 AS builder

WORKDIR /build
COPY requirements/build.txt requirements/build.txt
RUN python -m pip install --no-cache-dir --require-hashes -r requirements/build.txt

COPY LICENSE NOTICE README.md pyproject.toml ./
COPY src/ src/
RUN python -m build --wheel --no-isolation

FROM python:3.14-slim@sha256:d3400aa122fa42cf0af0dbe8ec3091b047eac5c8f7e3539f7135e86d855dc015 AS runtime

LABEL org.opencontainers.image.title="RigorFoundry"
LABEL org.opencontainers.image.description="Evidence-bound repository auditing and remediation planning"
LABEL org.opencontainers.image.source="https://github.com/anulum/rigor-foundry"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="ANULUM / Fortis Studio"

# Keep this snapshot date aligned with the pinned base image's debian.sources.
RUN sed -i \
        -e 's|URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20260714T000000Z|g' \
        -e 's|URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20260714T000000Z|g' \
        /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 rigor

COPY --from=builder /build/dist/*.whl /tmp/
COPY requirements/runtime.txt /tmp/runtime.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/runtime.txt \
    && python -m pip install --no-cache-dir --no-deps /tmp/*.whl \
    && rm -f /tmp/runtime.txt \
    && rm -f /tmp/*.whl

WORKDIR /workspace
USER rigor

HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=3 \
    CMD rigor --help >/dev/null || exit 1

ENTRYPOINT ["rigor"]
CMD ["--help"]
