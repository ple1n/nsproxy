# strip before release
strip ./target/release/sproxy
# dont strip /nsproxy
# otherwise no backtrace. sproxy is trivial
mkdir release
cp ./target/release/sproxy ./release
cp ./target/release/nsproxy ./release