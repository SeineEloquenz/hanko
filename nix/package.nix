{
  lib,
  rustPlatform,
  cacert,
  pname ? "hanko",
}:

let
  fs = lib.fileset;
  root = ../.;
  descriptions = {
    hanko = "Signs Android artifacts for verified GitHub Actions jobs and Kanidm users";
    hanko-sign = "Signs Android artifacts on a hanko server after logging in through Kanidm";
  };
in
rustPlatform.buildRustPackage {
  inherit pname;
  version = (lib.importTOML ../Cargo.toml).workspace.package.version;

  src = fs.toSource {
    inherit root;
    fileset = fs.unions [
      (root + "/Cargo.toml")
      (root + "/Cargo.lock")
      (root + "/crates")
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;
  cargoBuildFlags = [
    "-p"
    pname
  ];
  cargoTestFlags = [
    "-p"
    pname
  ];

  # reqwest refuses to build a client without system CA certificates, even when tests never connect.
  nativeCheckInputs = [ cacert ];

  meta = {
    description = descriptions.${pname};
    mainProgram = pname;
  };
}
