FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY wsrelay.c /src/wsrelay.c
RUN gcc -O2 -o /wsrelay /src/wsrelay.c
FROM debian:bookworm-slim
COPY --from=build /wsrelay /wsrelay
CMD ["/wsrelay"]
