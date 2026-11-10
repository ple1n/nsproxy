{
  description = "Flake for protocols that nsproxy may use";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.lokinet = {
    url = "git+file:./external/lokinet?allRefs=1&submodules=1";
    flake = false;
  };
  inputs.socks6 = {
    url = "git+file:./external/socks6?rev=9a6e7fcff4021cbfdb13f6674e4d7d72a93abfc0";
    flake = false;
  };
  inputs.daemon = {
    url = "path:./external/lokinet-socks6d";
    flake = false;
  };
  inputs.ipstack = {
    url = "git+file:./crates/ipstack?allRefs=1";
    flake = false;
  };

  outputs = { self, nixpkgs, lokinet, socks6, daemon, ipstack }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          lokinetLibrary = pkgs.stdenv.mkDerivation {
            pname = "lokinet-embedded";
            version = "0.9.16";
            src = lokinet;
            nativeBuildInputs = [
              pkgs.cmake
              pkgs.ninja
              pkgs.pkg-config
            ];
            buildInputs = [
              pkgs.curl
              pkgs.libuv
              pkgs.libsodium
              pkgs.nettle
              pkgs.unbound
              pkgs.libxcrypt
              pkgs.zstd
              pkgs.zeromq
            ];
            cmakeFlags = [
              "-DBUILD_DAEMON=OFF"
              "-DBUILD_LIBLOKINET=ON"
              "-DWITH_TESTS=OFF"
              "-DWITH_HIVE=OFF"
              "-DUSE_JEMALLOC=OFF"
              "-DNATIVE_BUILD=OFF"
              "-DWITH_SYSTEMD=OFF"
              "-DSUBMODULE_CHECK=OFF"
              "-DBUILD_SHARED_LIBS=ON"
              "-DOXEN_LOGGING_FMT_HEADER_ONLY=ON"
              "-DOXEN_LOGGING_SPDLOG_HEADER_ONLY=ON"
              "-DCMAKE_INSTALL_LIBDIR=lib"
            ];
          };
          daemonSource = pkgs.runCommand "lokinet-socks6d-source" { } ''
            mkdir -p "$out/external/lokinet-socks6d" "$out/crates/ipstack" "$out/external"
            cp -R ${daemon}/. "$out/external/lokinet-socks6d/"
            cp -R ${ipstack}/. "$out/crates/ipstack/"
            cp -R ${lokinet.outPath}/. "$out/external/lokinet/"
            cp -R ${socks6}/. "$out/external/socks6/"
          '';
          socks6LabSource = pkgs.runCommand "socks6-lab-source" { } ''
            mkdir -p "$out/external/socks6-lab" "$out/external"
            cp -R ${self}/external/socks6-lab/. "$out/external/socks6-lab/"
            cp -R ${socks6}/. "$out/external/socks6/"
          '';
          lokinetSocks6d = pkgs.rustPlatform.buildRustPackage {
            pname = "lokinet-socks6d";
            version = "0.1.0";
            src = daemonSource;
            sourceRoot = "lokinet-socks6d-source/external/lokinet-socks6d";
            cargoLock.lockFile = "${daemon}/Cargo.lock";
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ lokinetLibrary ];
            PKG_CONFIG_PATH = "${lokinetLibrary}/lib/pkgconfig";
            meta = {
              description = "User-launched SOCKS6 daemon backed by Lokinet";
              license = pkgs.lib.licenses.gpl3Only;
              mainProgram = "lokinet-socks6d";
              platforms = systems;
            };
          };
          socks6LabPackage = pkgs.rustPlatform.buildRustPackage {
            pname = "socks6-lab";
            version = "0.1.0";
            src = socks6LabSource;
            sourceRoot = "socks6-lab-source/external/socks6-lab";
            cargoLock.lockFile = "${self}/external/socks6-lab/Cargo.lock";
            meta = {
              description = "SOCKS6 testing and benchmarking tools";
              license = pkgs.lib.licenses.mit;
              mainProgram = "socks6-lab";
              platforms = systems;
            };
          };
        in
        {
          lokinet-socks6d = lokinetSocks6d;
          socks6-lab = socks6LabPackage;
        });
      apps = forAllSystems (system: {
        lokinet-socks6d = {
          type = "app";
          program = "${packages.${system}.lokinet-socks6d}/bin/lokinet-socks6d";
        };
        socks6-lab = {
          type = "app";
          program = "${packages.${system}.socks6-lab}/bin/socks6-lab";
        };
      });
    in
    {
      inherit apps packages;
    };
}
