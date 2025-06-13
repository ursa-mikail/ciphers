CARGO_DIR := bench

run:
	cargo run --release --manifest-path bench/Cargo.toml

build:
	cd $(CARGO_DIR) && cargo build --release

clean:
	cd $(CARGO_DIR) && cargo clean

time:
	cd $(CARGO_DIR) && /usr/bin/time -v cargo run --release

.PHONY: run build clean time

