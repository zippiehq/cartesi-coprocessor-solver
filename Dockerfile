FROM rust:1.85.1 as builder
RUN apt-get update && apt-get install -y protobuf-compiler clang curl

WORKDIR /cartesi-coprocessor-solver

COPY /src /cartesi-coprocessor-solver/src
COPY /entrypoint.sh /cartesi-coprocessor-solver/entrypoint.sh
COPY /Cargo.toml /cartesi-coprocessor-solver/Cargo.toml
COPY /Cargo.lock /cartesi-coprocessor-solver/Cargo.lock
COPY /.cargo /cartesi-coprocessor-solver/.cargo
WORKDIR /cartesi-coprocessor-solver
RUN git config --global url."https://github.com/".insteadOf git@github.com:
RUN git config --global url."https://".insteadOf git://
RUN cargo build --release

FROM debian:bookworm
RUN apt-get update && apt-get install -y libssl3 ca-certificates
COPY --from=builder /cartesi-coprocessor-solver/target/release/cartesi-coprocessor-solver /cartesi-coprocessor-solver/cartesi-coprocessor-solver
COPY --from=builder /cartesi-coprocessor-solver/entrypoint.sh /entrypoint.sh

EXPOSE 3033
WORKDIR /cartesi-coprocessor-solver
CMD bash /entrypoint.sh