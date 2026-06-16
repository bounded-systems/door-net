{
  # door-net — the allowlist egress door (netd) as a pinned OCI image.
  #
  # Extracted from claude-box (epic prx-ii01, card 2). netd is the ONLY egress
  # path for boxes (--network=none + this door): a pinned bun proxy that enforces
  # a host allowlist (NETD_ALLOW). claude-box (the integrator) pins the published
  # image and runs the cross-door system tests. (peercred is a launcherd helper,
  # NOT part of netd — it stays with the claude-room core.)
  description = "door-net — the netd allowlist-egress door as a pinned OCI image";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/9f11f828c213641c2369a9f1fa31fe31557e3156";

  # netd needs only the engine + the runtime helper (no contract dep).
  inputs.guest-room.url = "github:bounded-systems/guest-room/5bc85b634a0a8d698243ba3b708f0420516308ec";
  inputs.guest-room.flake = false;
  inputs.door-kit.url = "github:bounded-systems/door-kit/a3ae40e5075e3dbded3db9a0d345f842984a646b";
  inputs.door-kit.flake = false;

  outputs = { self, nixpkgs, guest-room, door-kit }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forEach = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
      uid = 1000;
    in
    {
      packages = forEach (system:
        let pkgs = pkgsFor system;
        in {
          # netd-image — the allowlist egress proxy as a container.
          #   nix build .#netd-image && podman load -i result
          #   podman run -v doors:/run/doors netd
          netd-image =
            let
              netdTools = with pkgs; [ bun cacert coreutils bashInteractive ];

              netdEnv = pkgs.buildEnv {
                name = "netd-image-root";
                paths = netdTools;
                pathsToLink = [ "/bin" "/etc" "/share" "/lib" ];
              };

              netdSrc = pkgs.runCommand "netd-src" { } ''
                mkdir -p $out/app/netd $out/app/lib $out/app/guest-room
                cp ${./netd/netd.ts} $out/app/netd/netd.ts
                cp ${./lib/runtime.ts} $out/app/lib/runtime.ts
                cp ${./guest-room/daemon.ts} $out/app/guest-room/daemon.ts
                cp ${./guest-room/protocol.ts} $out/app/guest-room/protocol.ts
              '';

              netdEntrypoint = pkgs.writeShellScript "netd-entrypoint" ''
                exec bun /app/netd/netd.ts serve --socket "''${NETD_SOCK:-/run/doors/netd.sock}" "$@"
              '';
            in
            pkgs.dockerTools.buildLayeredImage {
              name = "netd";
              tag = "dev";

              contents = [ netdEnv netdSrc ];

              extraCommands = ''
                mkdir -p etc tmp run/doors
                chmod 1777 tmp
                cat > etc/passwd <<EOF
                root:x:0:0:root:/root:/bin/bash
                netd:x:${toString uid}:${toString uid}:netd:/app:/bin/bash
                EOF
                cat > etc/group <<EOF
                root:x:0:
                netd:x:${toString uid}:
                EOF
              '';

              fakeRootCommands = ''
                chown -R ${toString uid}:${toString uid} run/doors
              '';

              config = {
                Entrypoint = [ "${netdEntrypoint}" ];
                WorkingDir = "/app";
                User = "netd";
                Env = [
                  "HOME=/app"
                  "PATH=/bin"
                  "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                  "LANG=C.UTF-8"
                  "NETD_ALLOW=api.anthropic.com,.anthropic.com"
                ];
                Volumes = {
                  "/run/doors" = { };
                };
              };
            };

          default = self.packages.${system}.netd-image;
        });

      # ── sync apps (regenerate the vendored mirrors from the pinned inputs) ──
      apps.aarch64-darwin =
        let pkgs = pkgsFor "aarch64-darwin";
        in {
          sync-guest-room = {
            type = "app";
            program = "${pkgs.writeShellScriptBin "sync-guest-room" ''
              set -euo pipefail
              for f in daemon.ts protocol.ts; do
                install -m 644 ${guest-room}/$f "$PWD/guest-room/$f"; echo "synced guest-room/$f"
              done
            ''}/bin/sync-guest-room";
            meta.description = "Sync ./guest-room/ from the pinned guest-room input";
          };
          sync-door-kit = {
            type = "app";
            program = "${pkgs.writeShellScriptBin "sync-door-kit" ''
              set -euo pipefail
              install -m 644 ${door-kit}/lib/runtime.ts "$PWD/lib/runtime.ts"; echo "synced lib/runtime.ts"
            ''}/bin/sync-door-kit";
            meta.description = "Sync ./lib/runtime.ts from the pinned door-kit input";
          };
        };

      # ── mirror checks: the vendored dirs must match the pinned inputs ──
      checks.aarch64-darwin =
        let pkgs = pkgsFor "aarch64-darwin";
        in {
          guest-room-mirror = pkgs.runCommand "guest-room-mirror" { } ''
            for f in daemon.ts protocol.ts; do
              if ! diff -u ${guest-room}/$f ${./guest-room}/$f; then
                echo "guest-room/$f drifted — run: nix run .#sync-guest-room" >&2; exit 1
              fi
            done
            touch $out
          '';
          door-kit-mirror = pkgs.runCommand "door-kit-mirror" { } ''
            if ! diff -u ${door-kit}/lib/runtime.ts ${./lib}/runtime.ts; then
              echo "lib/runtime.ts drifted — run: nix run .#sync-door-kit" >&2; exit 1
            fi
            touch $out
          '';
        };
    };
}
