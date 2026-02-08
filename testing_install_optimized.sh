cargo b --bins -p nsproxy_core -r
cargo b -p diag --features egui-client --bin nsp-diag -r
sudo ./target/release/nsproxy install
install ./target/debug/nsp-diag ./install