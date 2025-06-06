rule ltp_dirtypipe_override: override {
  meta:
    description                          = "testcases/bin/dirtypipe"
    Linux_Exploit_CVE_2022_0847_e831c285 = "high"

  strings:
    $dirtypipe = "@dirtypipe.c"
    $ltp       = "LTPROOT                  Prefix for installed LTP (default: /opt/ltp)"

  condition:
    all of them
}

rule ltp_runsched_override: override {
  meta:
    description                                   = "testcases/bin/run_sched_cliserv.sh"
    SIGNATURE_BASE_WEBSHELL_ASPX_Proxyshell_Aug15 = "harmless"

  strings:
    $cmd = "pthcli 127.0.0.1 $LTPROOT/testcases/bin/data"

  condition:
    all of them
}
