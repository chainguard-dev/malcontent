rule foundry: override {
  meta:
    description          = "Foundry EVM toolkit binaries (anvil, cast, chisel, forge)"
    crypto_stealer_names = "harmless"

  strings:
    $evm_core = /foundry_evm_core/
    $config   = /FOUNDRY_CONFIG/

  condition:
    filesize < 120MB and all of them
}
