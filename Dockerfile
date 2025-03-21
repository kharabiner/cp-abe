FROM python:3.9-slim

WORKDIR /app

# 필요한 시스템 패키지 설치 (charm-crypto 의존성 추가)
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    flex \
    bison \
    libgmp-dev \
    libssl-dev \
    git \
    python3-dev \
    python3-setuptools \
    libssl-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# PBC 라이브러리 설치 (charm-crypto의 의존성)
# 직접 tar.gz 파일 다운로드로 변경
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar -xvf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14 && \
    ./configure && \
    make && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf pbc-0.5.14 pbc-0.5.14.tar.gz

# charm-crypto 설치 (Git 저장소에서 직접 마스터 브랜치 사용)
RUN git clone https://github.com/JHUISI/charm.git && \
    cd charm && \
    ./configure.sh && \
    make && \
    make install && \
    cd .. && \
    rm -rf charm

# 필요한 Python 패키지 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 파일 복사
COPY . .

# 실행 권한 부여
RUN chmod +x /app/main.py

CMD ["python", "main.py"]
