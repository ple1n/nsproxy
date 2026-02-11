cargo b --bins -p nsproxy-core
cargo b -p diag --features egui-client --bin nsp-diag
sudo ./target/debug/nsproxy install
install ./target/debug/nsp-diag ./install