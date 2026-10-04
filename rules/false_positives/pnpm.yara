rule pnpm_cli_bundle: override {
  meta:
    description              = "/usr/lib/node_modules/pnpm/dist/pnpm.cjs, the esbuild bundle of the pnpm CLI"
    many_complex_var_high    = "low"
    http_url_with_msi        = "low"
    http_url_with_powershell = "low"
    from_secret_key          = "low"
    POST_command_executer    = "low"

  strings:
    $err_pnpm       = /ERR_PNPM_/
    $workspace_yaml = /pnpm-workspace\.yaml/
    $resume_from    = /Command executed from given package/
    $pnpm_exe       = /@pnpm\/exe/
    $virtual_store  = /node_modules\/\.pnpm/

  condition:
    filesize < 10MB and all of them
}
