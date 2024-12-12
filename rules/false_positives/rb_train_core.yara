rule train_transports_local: override {
  meta:
    description                                    = "train-core-3.10.8.gem"
    SIGNATURE_BASE_Powershell_Susp_Parameter_Combo = "high"

  strings:
    $author1    = "# author: Dominik Richter"
    $author2    = "# author: Christoph Hartmann"
    $transports = "module Train::Transports"

  condition:
    filesize < 50KB and all of them
}
