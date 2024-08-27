# strip before release
strip ./target/release/sproxy
# dont strip /nsproxy
# otherwise no backtrace. sproxy is trivial
