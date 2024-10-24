rule make_win_ps1 : override {
  meta:
    description = "make-win.ps1"
    SECUINFRA_SUSP_Powershell_Base64_Decode = "medium"
  strings:
    $end = "END=OF=COMPILER"
    $registry = "gcr.io/kubeflow-images-public/centraldashboard"
    $repository = "https://github.com/avdaredevil/AP-Compiler"
    $start = "START=OF=COMPILER"
  condition:
    filesize < 10KB and all of them
}
