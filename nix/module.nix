{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.hanko;

  credential = name: "/run/credentials/hanko.service/${name}";

  auditLog = "/var/lib/hanko/audit.jsonl";

  timeoutOption =
    what:
    lib.mkOption {
      type = lib.types.ints.positive;
      default = 300;
      description = "Seconds a request may spend ${what}.";
    };

  formats = lib.unique (lib.mapAttrsToList (_: p: p.format) cfg.profiles);

  profileSettings = name: p: {
    inherit (p) format;
    package_name = p.packageName;
    keystore = {
      path = credential "${name}-keystore";
      inherit (p) alias;
      store_password_file = credential "${name}-store-password";
    }
    // lib.optionalAttrs (p.keyPasswordFile != null) {
      key_password_file = credential "${name}-key-password";
    };
    access = lib.filterAttrs (_: v: v != null) {
      github = lib.mapNullable (
        github: { repository_id = github.repositoryId; } // github.claims
      ) p.access.github;
      kanidm = p.access.kanidm;
    };
  };

  settings = lib.filterAttrs (_: v: v != null) {
    listen =
      if lib.hasInfix ":" cfg.host then
        "[${cfg.host}]:${toString cfg.port}"
      else
        "${cfg.host}:${toString cfg.port}";
    max_body_bytes = cfg.maxBodyBytes;
    max_concurrent = cfg.maxConcurrent;
    max_queued = cfg.maxQueued;
    upload_timeout_secs = cfg.uploadTimeout;
    queue_timeout_secs = cfg.queueTimeout;
    signing_timeout_secs = cfg.signingTimeout;
    audit_log = if cfg.auditLog then auditLog else null;
    notify_url = cfg.notifyUrl;
    github = lib.mapNullable (github: { inherit (github) audience; }) cfg.github;
    kanidm = lib.mapNullable (kanidm: {
      inherit (kanidm) url;
      client_id = kanidm.clientId;
    }) cfg.kanidm;
    profiles = lib.mapAttrs profileSettings cfg.profiles;
  };

  configFile = pkgs.runCommand "hanko.json" { } ''
    cp ${(pkgs.formats.json { }).generate "hanko.json" settings} $out
    ${lib.getExe cfg.package} --check $out
  '';

  credentials = lib.concatLists (
    lib.mapAttrsToList (
      name: p:
      [
        "${name}-keystore:${p.keystoreFile}"
        "${name}-store-password:${p.storePasswordFile}"
      ]
      ++ lib.optional (p.keyPasswordFile != null) "${name}-key-password:${p.keyPasswordFile}"
    ) cfg.profiles
  );

  githubPolicy = lib.types.submodule {
    options = {
      repositoryId = lib.mkOption {
        type = lib.types.ints.unsigned;
        description = "Numeric GitHub repository id that may sign. Ids survive renames, names do not.";
      };
      claims = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        default = { };
        example = {
          environment = "release";
          ref = "refs/heads/main";
        };
        description = ''
          Further GitHub OIDC claims the token must carry exactly. At least one of
          `environment`, `ref` or `job_workflow_ref` is required, so pushing an arbitrary
          branch cannot sign. Prefer `environment` with protection rules.
        '';
      };
    };
  };

  kanidmPolicy = lib.types.submodule {
    options.scope = lib.mkOption {
      type = lib.types.str;
      example = "sign";
      description = "Scope the Kanidm access token must carry.";
    };
  };

  profile = lib.types.submodule {
    options = {
      format = lib.mkOption {
        type = lib.types.enum [
          "aab"
          "apk"
        ];
        description = "Artifact type, signed with jarsigner (aab) or apksigner (apk).";
      };
      keystoreFile = lib.mkOption {
        type = lib.types.str;
        example = "/run/secrets/quits-upload.p12";
        description = "Keystore outside the Nix store, passed to the service as a systemd credential.";
      };
      storePasswordFile = lib.mkOption {
        type = lib.types.str;
        description = "File holding the keystore password.";
      };
      keyPasswordFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "File holding the key password, if it differs from the keystore password.";
      };
      alias = lib.mkOption {
        type = lib.types.str;
        description = "Key alias in the keystore.";
      };
      packageName = lib.mkOption {
        type = lib.types.str;
        example = "nz.eloque.quits";
        description = "Package name every artifact signed with this profile must have.";
      };
      access = {
        github = lib.mkOption {
          type = lib.types.nullOr githubPolicy;
          default = null;
          description = "GitHub Actions jobs allowed to sign.";
        };
        kanidm = lib.mkOption {
          type = lib.types.nullOr kanidmPolicy;
          default = null;
          description = "Kanidm users allowed to sign. Requires {option}`services.hanko.kanidm`.";
        };
      };
    };
  };
in
{
  options.services.hanko = {
    enable = lib.mkEnableOption "the hanko signing service";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The hanko package to run.";
    };

    host = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Address to listen on.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8470;
      description = "TCP port to listen on.";
    };

    github = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.submodule {
          options.audience = lib.mkOption {
            type = lib.types.str;
            example = "https://sign.example.com";
            description = "Audience GitHub OIDC tokens must be requested for.";
          };
        }
      );
      default = null;
      description = "GitHub Actions OIDC tokens hanko accepts.";
    };

    maxBodyBytes = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.positive;
      default = null;
      description = "Largest accepted artifact in bytes. Null keeps the built-in 200 MiB.";
    };

    maxConcurrent = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.positive;
      default = null;
      description = "Signings that may run at once. Null keeps the built-in 1.";
    };

    maxQueued = lib.mkOption {
      type = lib.types.nullOr lib.types.ints.unsigned;
      default = null;
      description = ''
        Requests that may wait for a signing slot while holding an upload on disk.
        Null keeps the built-in 4.
      '';
    };

    uploadTimeout = timeoutOption "waiting for an upload slot and uploading";
    queueTimeout = timeoutOption "waiting for a signing slot";
    signingTimeout = timeoutOption "signing";

    auditLog = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to record every signature in `${auditLog}` before returning it.";
    };

    notifyUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "https://ntfy.example.com/hanko";
      description = "URL that receives a plain-text POST for every signature, e.g. an ntfy topic.";
    };

    kanidm = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.submodule {
          options = {
            url = lib.mkOption {
              type = lib.types.str;
              example = "https://idm.example.com/oauth2/openid/hanko";
              description = "Per-client Kanidm issuer URL.";
            };
            clientId = lib.mkOption {
              type = lib.types.str;
              default = "hanko";
              description = "Kanidm OAuth2 client id, which is also the token audience.";
            };
          };
        }
      );
      default = null;
      description = "Kanidm OAuth2 client whose access tokens hanko accepts.";
    };

    profiles = lib.mkOption {
      type = lib.types.attrsOf profile;
      default = { };
      description = "Signing profiles, addressed as `/v1/sign/<name>`.";
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "hanko=info";
      description = "Value for `RUST_LOG`.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to open {option}`port` in the firewall.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.hanko = {
      description = "hanko signing service";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      path = [
        pkgs.jdk_headless
      ]
      ++ lib.optional (lib.elem "aab" formats) pkgs.bundletool
      ++ lib.optionals (lib.elem "apk" formats) [
        pkgs.aapt
        pkgs.apksigner
      ];

      environment = {
        RUST_LOG = cfg.logLevel;
        HOME = "/tmp";
      };

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} ${configFile}";
        LoadCredential = credentials;

        DynamicUser = true;
        Restart = "on-failure";
        RestartSec = 5;
        TimeoutStopSec = cfg.uploadTimeout + cfg.queueTimeout + cfg.signingTimeout + 60;
        StateDirectory = lib.mkIf cfg.auditLog "hanko";

        AmbientCapabilities = lib.mkIf (cfg.port < 1024) [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = if cfg.port < 1024 then [ "CAP_NET_BIND_SERVICE" ] else [ "" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        # The JVM's JIT needs writable executable memory.
        MemoryDenyWriteExecute = false;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
        UMask = "0077";
      };
    };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
  };
}
