FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y && apt-get update -y
RUN apt install -y libstdc++-10-dev \
    make \
    wget \
    xz-utils \
    patch \
    cmake \
    lsb-release software-properties-common gnupg \
    g++

ARG WORKDIR=/workspace/
ARG UID=1000
ARG GID=1000
ARG UNAME="user"
# Create user
RUN groupadd -g $GID -o $UNAME || groupmod -g $GID $UNAME
RUN useradd -m -u $UID -g $GID -o -s /bin/bash $UNAME || usermod -u $UID $UNAME

# Copy all files from GREBE/analyzer repository.
RUN mkdir -p $WORKDIR
ADD ./* $WORKDIR
ADD ./src $WORKDIR

WORKDIR $WORKDIR
# Install latest stable LLVM from upstream.
RUN cd $WORKDIR && bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"

RUN chown -R $UNAME:$UNAME $WORKDIR
# Switch from root to regular user.
USER $UNAME

# Fetch LLVM 10.0.1 source code.
RUN cd $WORKDIR && wget https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/llvm-project-10.0.1.tar.xz
RUN cd $WORKDIR && tar -xf llvm-project-*.tar.xz && rm llvm-project-*.tar.xz
# Apply custom patch to LLVM to generate -O0 bitcode.
RUN cd llvm-project-* && wget https://raw.githubusercontent.com/Markakd/LLVM-O0-BitcodeWriter/master/WriteBitcode.patch
RUN cd $WORKDIR && cd llvm-project-* && patch -p 1 < WriteBitcode.patch
# Compile custom clang compiler which can generate -O0 bitcode.
RUN cd $WORKDIR && cd llvm-project-* && mkdir -p build && cd build && cmake -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ../llvm && make -j $(nproc)

# Run make install as root to install LLVM headers.
USER root
RUN cd $WORKDIR && cd llvm-project-* && cd build && make install
# Run the remainder of the build as user to build the analyzer binary.
USER $UNAME
RUN cd $WORKDIR && make

