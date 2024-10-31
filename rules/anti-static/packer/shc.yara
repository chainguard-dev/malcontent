rule shc: high {
  meta:
    description                          = "Binary generated with SHC (Shell Script Compiler)"
    ref                                  = "https://github.com/neurobin/shc"
    hash_2023_Linux_Malware_Samples_1328 = "1328f1c2c9fe178f13277c18847dd9adb9474f389985e17126fcb895aac035f2"
    hash_2023_Linux_Malware_Samples_77b8 = "77b881109c2141aef8a86263de75e041794556489055c1488f1d36feb7d70dd3"
    hash_2023_Linux_Malware_Samples_edbe = "edbee3b92100cc9a6a8a3c1a5fc00212627560c5e36d29569d497613ea3e3c16"

  strings:
    $ref = "argv[0] nor $_"

  condition:
    $ref
}
