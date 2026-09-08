FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/lib/llvm-15/bin:/opt/tea121/bin:${PATH}" \
    LLVM_DIR="/usr/lib/llvm-15/lib/cmake/llvm" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates wget gnupg lsb-release software-properties-common \
       build-essential cmake ninja-build python3 python3-pip python3-venv \
    && wget -qO- https://apt.llvm.org/llvm.sh | bash -s -- 15 \
    && apt-get install -y --no-install-recommends clang-15 llvm-15 llvm-15-dev llvm-15-tools lld-15 \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install -y --no-install-recommends libffi-dev zlib1g-dev libtinfo-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY analyzer /workspace/analyzer
COPY backend /workspace/backend
COPY contracts /workspace/contracts
COPY docs /workspace/docs
COPY scripts /workspace/scripts

RUN cmake -S /workspace/analyzer -B /tmp/tea121-build -G Ninja \
      -DLLVM_DIR=/usr/lib/llvm-15/lib/cmake/llvm \
    && cmake --build /tmp/tea121-build --target tea121-extract \
    && install -Dm755 /tmp/tea121-build/tea121-extract /usr/local/bin/tea121-extract \
    && python3 -m pip install --no-cache-dir --upgrade pip \
    && python3 -m pip install --no-cache-dir /workspace/analyzer \
    && python3 -m pip install --no-cache-dir /workspace/backend \
    && python3 -m pip install --no-cache-dir pytest \
    && rm -rf /tmp/tea121-build

ENTRYPOINT ["tea121"]
CMD ["--version"]
