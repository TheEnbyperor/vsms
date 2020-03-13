FROM clux/muslrust as build

COPY ./ ./
RUN cargo build --release --target=x86_64-unknown-linux-musl
RUN mkdir -p /build-out
RUN cp target/x86_64-unknown-linux-musl/release/vsms /build-out/

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /build-out/vsms /
ENTRYPOINT ["/vsms"]