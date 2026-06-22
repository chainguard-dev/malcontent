rule redocly_cli_faker_data: override {
  meta:
    description          = "redocly-cli bundles @faker-js/faker which contains periodic table and locale data"
    crypto_stealer_names = "harmless"

  strings:
    $faker    = "@faker-js/faker"
    $periodic = "atomicNumber"

  condition:
    filesize < 5MB and all of them
}
