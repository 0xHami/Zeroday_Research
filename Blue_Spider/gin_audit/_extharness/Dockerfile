# syntax=docker/dockerfile:1
#
# Extended gin harness for stage-10 conditional/primitive findings. Links the LOCAL gin
# source (audit target) via go.mod replace; gin is supplied as the "ginsrc" additional
# build context so targets/gin stays pristine (same approach as setup/Dockerfile).

FROM golang:1.26-bookworm AS build
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY --from=ginsrc . /src/gin
RUN rm -rf /src/gin/.git
COPY main.go go.mod /src/harness/
WORKDIR /src/harness
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -o /out/ginextharness .

FROM debian:bookworm-slim
RUN useradd -r -u 10002 -m harness \
    && mkdir -p /app/uploads /app/public \
    && printf 'public file\n' > /app/public/hello.txt \
    && chown -R harness:harness /app
WORKDIR /app
COPY --from=build /out/ginextharness /usr/local/bin/ginextharness
USER harness
EXPOSE 8090 8091 8092 8093 8094 8095 8096 8097
CMD ["/usr/local/bin/ginextharness"]
