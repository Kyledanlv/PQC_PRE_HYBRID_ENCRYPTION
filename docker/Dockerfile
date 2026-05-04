FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

#Update system and build essentials
RUN apt-get update && apt-get install -y \
   build-essential cmake ninja-build gcc git \
   python3-full python3-pip libssl-dev \
   tcpdump iproute2 \
   && rm -rf /var/lib/apt/lists/*

#Build C core inside Container
WORKDIR /opt
RUN git clone -b main https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    ninja && \
    ninja install && \
    ldconfig

#Set up Symlink to replace the .bashrc
ENV LD_LIBRARY_PATH="/usr/local/lib"

WORKDIR /app

RUN mkdir -p /app/data
#Initiate Python virtual enviroment
RUN python3 -m venv /app/venv

#Activate venv permanently inside Container
ENV PATH="/app/venv/bin:$PATH"

#Copy config file and install Python libraries
COPY requirements.txt .
RUN pip install --default-timeout=1000 --no-cache-dir -r requirements.txt

#Copy all the source file
COPY src/ ./src/

CMD ["python3", "src/test_run.py"]



