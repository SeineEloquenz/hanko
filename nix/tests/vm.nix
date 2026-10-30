{ pkgs, module }:

let
  issuerPort = 8000;
  issuer = "http://127.0.0.1:${toString issuerPort}/oauth2/openid/hanko";

  issuerRoot = pkgs.runCommand "fake-kanidm" { } ''
    dir=$out/oauth2/openid/hanko
    mkdir -p $dir/.well-known
    cp ${../../crates/hanko/tests/fixtures/kanidm-jwks.json} $dir/public_key.jwk
    echo '{"issuer": "${issuer}", "jwks_uri": "${issuer}/public_key.jwk"}' \
      > $dir/.well-known/openid-configuration
  '';

  keystore = pkgs.runCommand "upload.p12" { nativeBuildInputs = [ pkgs.jdk_headless ]; } ''
    keytool -genkeypair -keystore $out -storetype PKCS12 -storepass storepass \
      -alias upload -keyalg RSA -keysize 2048 -validity 1 -dname CN=vm-test
  '';

  # Stands in for android.jar, which aapt2 needs to resolve the manifest attributes.
  frameworkAttrs = pkgs.writeText "attrs.xml" ''
    <resources>
      <attr name="hasCode" format="boolean" />
      <attr name="versionCode" format="integer" />
      <public type="attr" name="hasCode" id="0x0101000c" />
      <public type="attr" name="versionCode" id="0x0101021b" />
    </resources>
  '';

  manifest = pkgs.writeText "AndroidManifest.xml" ''
    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
      <application android:hasCode="false" />
    </manifest>
  '';

  artifacts =
    pkgs.runCommand "unsigned-artifacts"
      {
        nativeBuildInputs = [
          pkgs.aapt
          pkgs.bundletool
          pkgs.unzip
          pkgs.zip
        ];
      }
      ''
        mkdir -p $out values base/manifest
        cp ${frameworkAttrs} values/attrs.xml
        echo '<manifest package="android" />' > framework-manifest.xml
        aapt2 compile -o framework.zip values/attrs.xml
        aapt2 link --manifest framework-manifest.xml -o framework.apk framework.zip

        link() { aapt2 link -I framework.apk --version-code 1 --manifest ${manifest} "$@"; }
        link -o $out/app.apk
        link --proto-format -o proto.apk

        (cd base && unzip -q ../proto.apk && mv AndroidManifest.xml manifest/ && zip -qr ../base.zip .)
        bundletool build-bundle --modules=base.zip --output=$out/app.aab
      '';

  mintToken =
    pkgs.writers.writePython3 "mint-token"
      {
        libraries = ps: [
          ps.pyjwt
          ps.cryptography
        ];
      }
      ''
        import time

        import jwt

        now = int(time.time())
        claims = {
            "iss": "${issuer}",
            "sub": "00000000-0000-0000-0000-000000000001",
            "aud": "hanko",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": "session",
            "client_id": "hanko",
            "scope": "openid sign",
        }
        key = open("${../../crates/hanko/tests/fixtures/kanidm-key.pem}").read()
        headers = {"kid": "kanidm-test", "typ": "at+jwt"}
        print(jwt.encode(claims, key, algorithm="ES256", headers=headers))
      '';

  profile = format: {
    inherit format;
    keystoreFile = "${keystore}";
    storePasswordFile = "${pkgs.writeText "store.pass" "storepass"}";
    alias = "upload";
    packageName = "com.example";
    access.kanidm.scope = "sign";
  };
in
pkgs.testers.runNixOSTest {
  name = "hanko";

  nodes.machine = {
    imports = [ module ];

    services.hanko = {
      enable = true;
      kanidm.url = issuer;
      profiles.aab = profile "aab";
      profiles.apk = profile "apk";
    };

    systemd.services.fake-kanidm = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server ${toString issuerPort} --bind 127.0.0.1 --directory ${issuerRoot}";
    };

    environment.systemPackages = [
      pkgs.curl
      pkgs.jdk_headless
      pkgs.apksigner
    ];
  };

  testScript = ''
    def post(profile, args, output="/dev/null"):
        return machine.succeed(
            f"curl -s -o {output} -w '%{{http_code}}' {args} http://127.0.0.1:8470/v1/sign/{profile}"
        )

    machine.wait_for_unit("hanko.service")
    machine.wait_for_unit("fake-kanidm.service")
    machine.wait_for_open_port(8470)
    machine.wait_for_open_port(${toString issuerPort})

    machine.succeed("curl -sf http://127.0.0.1:8470/healthz")
    assert post("aab", "--data x") == "401"

    token = machine.succeed("${mintToken}").strip()
    auth = f"-H 'Authorization: Bearer {token}'"
    assert post("aab", f"{auth} --data-binary 'not a bundle'") == "422"

    # Only a JVM that survived the service sandbox can print this.
    machine.succeed("journalctl -u hanko.service | grep -q 'Bundle is not a valid zip file'")

    assert post("aab", f"{auth} --data-binary @${artifacts}/app.aab", "/tmp/app.aab") == "200"
    machine.succeed("jarsigner -verify /tmp/app.aab | grep -q 'jar verified.'")
    machine.succeed("keytool -printcert -jarfile /tmp/app.aab | grep -q CN=vm-test")

    assert post("apk", f"{auth} --data-binary @${artifacts}/app.apk", "/tmp/app.apk") == "200"
    machine.succeed("apksigner verify --print-certs /tmp/app.apk | grep -q CN=vm-test")

    assert machine.succeed("wc -l < /var/lib/hanko/audit.jsonl").strip() == "2"
    machine.succeed("grep -q '\"profile\":\"apk\"' /var/lib/hanko/audit.jsonl")
  '';
}
