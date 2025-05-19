rule zip_a_folder: medium {
  meta:
    description = "may zip up a local directory for exiltration"
    ref         = "https://www.npmjs.com/package/zip-a-folder"
    filetypes   = "js,ts"

  strings:
    $zip_a_fold = /zip-a-fold[a-z]{0,2}/
    $zipPath    = "zipPath" fullword

  condition:
    any of them
}
