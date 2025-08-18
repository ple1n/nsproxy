mkdir -p release
cp ./target/release/sproxy ./release
cp ./target/release/nsproxy ./release
cp ./release/nsproxy ./release/nsproxy_debug
strip ./release/sproxy
strip ./release/nsproxy