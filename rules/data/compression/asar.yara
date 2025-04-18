rule asar {
  meta:
    description = "works with ASAR (Electron Archive) files"
    ref         = "https://www.electronjs.org/docs/latest/tutorial/asar-archives"

  strings:
    $ref_extract = "asar.extractAll" fullword
    $ref_create  = "asar.createPackage" fullword

  condition:
    any of them
}
