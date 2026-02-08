cargo b --bins -p nsproxy_core
cargo b -p diag --features egui-client --bin nsp-diag
sudo ./target/debug/nsproxy install
install ./target/debug/nsp-diag ./install