{
  lib,
  buildGoModule,
  nix-gitignore,
  ...
}:

buildGoModule {
  pname = "tsidp";
  version = "dev";
  src = nix-gitignore.gitignoreSource [ ] ../.;
  meta.mainProgram = "tsidp";
  ldflags =
    let
      tsVersion =
        with builtins;
        head (match ".*tailscale.com v([0-9]+\.[0-9]+\.[0-9]+-?[a-zA-Z]?).*" (readFile ../go.mod));
    in
    [
      "-w"
      "-s"
      "-X tailscale.com/version.longStamp=${tsVersion}"
      "-X tailscale.com/version.shortStamp=${tsVersion}"
    ];
  vendorHash = lib.fileContents ../go.mod.sri;
}
