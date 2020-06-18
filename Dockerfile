FROM ekidd/rust-musl-builder:1.44.0

COPY --chown=rust:rust . ./

CMD ["cargo", "build", "--release"]