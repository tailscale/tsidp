{
  description = "tsidp - A simple OIDC / OAuth Identity Provider (IdP) server for your tailnet.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs = {
    self,
    nixpkgs,
    systems,
  }: let
    go125Version = "1.24.7";
    goHash = "sha256-Ko9Q2w+IgDYHxQ1+qINNy3vUg8a0KKkeNg/fhiS0ZGQ=";
    eachSystem = f:
      nixpkgs.lib.genAttrs (import systems) (system:
        f (import nixpkgs {
          system = system;
          overlays = [
            (final: prev: {
              go_1_24 = prev.go_1_24.overrideAttrs {
                version = go125Version;
                src = prev.fetchurl {
                  url = "https://go.dev/dl/go${go125Version}.src.tar.gz";
                  hash = goHash;
                };
              };
            })
          ];
        }));
  in {
    formatter = eachSystem (pkgs: pkgs.nixpkgs-fmt);

    packages = eachSystem (pkgs: {
      default = pkgs.buildGo124Module {
        pname = "tsidp";
        version =
          if (self ? shortRev)
          then self.shortRev
          else "dev";
        src = pkgs.nix-gitignore.gitignoreSource [] ./.;
        ldflags = let
          tsVersion = with builtins;
            head (match ".*tailscale.com v([0-9]+\.[0-9]+\.[0-9]+-?[a-zA-Z]?).*" (readFile ./go.mod));
        in [
          "-w"
          "-s"
          "-X tailscale.com/version.longStamp=${tsVersion}"
          "-X tailscale.com/version.shortStamp=${tsVersion}"
        ];
        vendorHash = "sha256-obtcJTg7V4ij3fGVmZMD7QQwKJX6K5PPslpM1XKCk9Q="; # SHA based on vendoring go.mod
      };
    });

    overlays.default = final: prev: {
      tsidp = self.packages.${prev.stdenv.hostPlatform.system}.default;
    };

    nixosModules.default = {
      config,
      lib,
      pkgs,
      ...
    }: let
      cfg = config.services.tsidp;
    in {
      options.services.tsidp = {
        enable = lib.mkEnableOption "Enable tsidp service";

        package = lib.mkOption {
          type = lib.types.package;
          default = pkgs.tsidp;
          description = "The tsidp package to use.";
        };

        dataDir = lib.mkOption {
          type = lib.types.path;
          default = "/var/lib/tsidp";
          description = "The directory to store tsidp data.";
        };

        user = lib.mkOption {
          type = lib.types.str;
          default = "tsidp";
          description = "The user to run the tsidp service as.";
        };

        group = lib.mkOption {
          type = lib.types.str;
          default = "tsidp";
          description = "The group to run the tsidp service as.";
        };

        enableDebug = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Enable debug printing of requests to the server.";
        };

        enableSts = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Enable OIDC STS token exchange support.";
        };

        hostName = lib.mkOption {
          type = lib.types.str;
          default = "idp";
          description = "The hostname to use for the tsidp server.";
        };

        funnel = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Enable Tailscale Funnel support.";
        };

        port = lib.mkOption {
          type = lib.types.int;
          default = 443;
          description = "The port to run the tsidp server on.";
        };

        localPort = lib.mkOption {
          type = lib.types.int;
          default = -1;
          description = "allow requests from localhost, -1 disables this.";
        };

        verbose = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Enable verbose logging.";
        };
      };

      config = lib.mkIf cfg.enable {
        nixpkgs.overlays = [self.overlays.default];

        users.groups."${cfg.group}" = {};
        users.users."${cfg.user}" = {
          home = cfg.dataDir;
          group = cfg.group;
          createHome = true;
          isSystemUser = true;
          isNormalUser = false;
          description = "tsidp service user";
        };

        systemd.services.tsidp = {
          description = "tsidp service";
          after = ["network.target"];
          wants = ["network.target"];
          wantedBy = ["multi-user.target" "network-online.target"];
          environment = {
            TAILSCALE_USE_WIP_CODE = "1";
          };
          serviceConfig = {
            User = cfg.user;
            Group = cfg.group;
            Restart = "always";
            RestartSec = "15";
            WorkingDirectory = "${cfg.dataDir}";
            ExecStart = ''
              ${cfg.package}/bin/tsidp \
                --dir ${cfg.dataDir} \
                ${lib.optionalString (cfg.hostName != "idp") ("--hostname " + cfg.hostName)} \
                ${lib.optionalString (cfg.port != 443) ("--port " + toString cfg.port)} \
                ${lib.optionalString (cfg.localPort != -1) ("--local-port " + toString cfg.localPort)} \
                ${lib.optionalString (cfg.enableDebug) "--debug"} \
                ${lib.optionalString (cfg.verbose) "--verbose"} \
                ${lib.optionalString (cfg.enableSts) "--enable-sts"} \
                ${lib.optionalString (cfg.funnel) "--funnel"}
            '';
          };
        };
      };
    };
  };
}
