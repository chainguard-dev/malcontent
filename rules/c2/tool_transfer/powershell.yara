rule powershell_base64_dropper: critical {
  meta:
    description = "Powershell base64 dropper"
    filetypes   = "ps1"

  strings:
    $base64     = "FromBase64String"
    $write      = "WriteAllBytes"
    $io_file    = "System.IO.File"
    $start_proc = "Start-Process"
    $file_path  = "FilePath"

  condition:
    filesize < 2KB and all of them
}
