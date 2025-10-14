mkdir -p release
cargo b -r --bins -p nsproxy_core
cp ./target/release/sproxy ./release
cp ./target/release/nsproxy ./release
cp ./release/nsproxy ./release/nsproxy_debug
strip ./release/sproxy
strip ./release/nsproxy
upx ./release/sproxy
upx ./release/nsproxy
ls -lh release