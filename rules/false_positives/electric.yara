rule electric_phoenix_eex: override {
  meta:
    description                      = "app/lib/phoenix-*/priv/templates/phx.gen.release/rel/migrate.sh.eex"
    SIGNATURE_BASE_WEBSHELL_ASP_Nano = "harmless"

  strings:
    $otp_app         = "otp_app"
    $app_namespace   = "app_namespace"
    $release_migrate = "Release.migrate"

  condition:
    filesize < 500 and all of them
}
