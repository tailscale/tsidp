{
  lib,
  config,
  pkgs,
  ...
}:
let
  inherit (lib)
    getExe
    mkEnableOption
    mkIf
    mkOption
    mkPackageOption
    optional
    ;
  inherit (lib.types)
    str
    port
    bool
    enum
    nullOr
    ;

  cfg = config.services.tsidp;

  stateDir = "/var/lib/tsidp";
in
{
  options.services.tsidp = {
    enable = mkEnableOption "tsidp server";

    package = mkOption {
      type = lib.types.package;
      default = pkgs.tsidp;
      description = "Package to use for the tsidp service.";
    };

    environmentFile = mkOption {
      type = nullOr lib.types.path;
      description = ''
        Path to an environment file loaded for the tsidp service.

        This can be used to securely store tokens and secrets outside of the world-readable Nix store.

        Example contents of the file:
        ```
        TS_AUTH_KEY=YOUR_TAILSCALE_AUTHKEY
        ```
      '';
      default = null;
      example = "/run/secrets/tsidp";
    };

    settings = {
      hostName = mkOption {
        type = str;
        default = "idp";
        description = ''
          The hostname to use for the tsnet node.
        '';
      };

      port = mkOption {
        type = port;
        default = 443;
        description = ''
          Port to listen on (default: 443).
        '';
      };

      localPort = mkOption {
        type = nullOr port;
        default = null;
        description = "Listen on localhost:<port>.";
      };

      useLocalTailscaled = mkOption {
        type = bool;
        description = ''
          Use local tailscaled instead of tsnet.
        '';
        default = false;
      };

      unixSocket = mkOption {
        type = nullOr lib.types.path;
        default = null;
        description = "Path to unix socket to listen on";
      };

      disableTCP = mkOption {
        type = nullOr bool;
        default = null;
        description = "Disable the TCP Listeners on tsnet and tailscaled";
      };

      serverURL = mkOption {
        type = nullOr str;
        default = null;
        description = "Server URL to use instead of the tailscale FDQN";
      };

      enableFunnel = mkOption {
        type = bool;
        default = false;
        description = ''
          Use Tailscale Funnel to make tsidp available on the public internet so it works with SaaS products.
        '';
      };

      enableSts = mkOption {
        type = bool;
        default = true;
        description = ''
          Enable OAuth token exchange using RFC 8693.
        '';
      };

      logLevel = mkOption {
        type = enum [
          "debug"
          "info"
          "warn"
          "error"
        ];
        description = ''
          Set logging level: debug, info, warn, error.
        '';
        default = "info";
      };

      debugAllRequests = mkOption {
        type = bool;
        description = ''
          For development. Prints all requests and responses.
        '';
        default = false;
      };

      debugTsnet = mkOption {
        type = bool;
        description = ''
          For development. Enables debug level logging with tsnet connection.
        '';
        default = false;
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.settings.useLocalTailscaled -> config.services.tailscale.enable == true;
        message = "Tailscale service must be enabled if services.tsidp.settings.useLocalTailscaled is used.";
      }
    ];

    systemd.services.tsidp =
      let
        deps = [
          "network.target"
        ]
        ++ optional (cfg.settings.useLocalTailscaled) "tailscaled.service";
      in
      {
        description = "tsidp";
        after = deps;
        wants = deps;
        wantedBy = [
          "multi-user.target"
          "network-online.target"
        ];
        restartTriggers = [
          cfg.package
          cfg.environmentFile
        ];

        environment = {
          HOME = stateDir;
          TAILSCALE_USE_WIP_CODE = "1";
        };

        serviceConfig = {
          Type = "simple";
          ExecStart =
            let
              args = lib.cli.toGNUCommandLineShell { mkOptionName = k: "-${k}"; } {
                hostname = cfg.settings.hostName;
                port = cfg.settings.port;
                server-url = cfg.settings.serverURL;
                local-port = cfg.settings.localPort;
                use-local-tailscaled = cfg.settings.useLocalTailscaled;
                unix-socket = cfg.settings.unixSocket;
                disable-tcp = cfg.settings.disableTCP;
                funnel = cfg.settings.enableFunnel;
                enable-sts = cfg.settings.enableSts;
                log = cfg.settings.logLevel;
                debug-all-requests = cfg.settings.debugAllRequests;
                debug-tsnet = cfg.settings.debugTsnet;
                dir = stateDir;
              };
            in
            "${getExe cfg.package} ${args}";
          Restart = "always";
          RestartSec = "15";

          DynamicUser = true;
          StateDirectory = baseNameOf stateDir;
          WorkingDirectory = stateDir;
          ReadWritePaths = mkIf (cfg.settings.useLocalTailscaled) [
            "/var/run/tailscale"
            "/var/lib/tailscale"
          ];
          BindPaths = mkIf (cfg.settings.useLocalTailscaled) [
            "/var/run/tailscale:/var/run/tailscale"
          ];

          EnvironmentFile = mkIf (cfg.environmentFile != null) cfg.environmentFile;

          AmbientCapabilities = "";
          CapabilityBoundingSet = "";
          DeviceAllow = "";
          DevicePolicy = "closed";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateNetwork = false;
          PrivateTmp = true;
          PrivateUsers = true;
          PrivateDevices = true;
          ProtectHome = true;
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectKernelTunables = true;
          ProtectSystem = "strict";
          ProtectHostname = true;
          ProtectProc = "invisible";
          ProcSubset = "all";
          RestrictAddressFamilies = [
            "AF_INET"
            "AF_INET6"
            "AF_UNIX"
            "AF_NETLINK"
          ];
          RestrictRealtime = true;
          RestrictNamespaces = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" ];
        };
      };
  };
}
