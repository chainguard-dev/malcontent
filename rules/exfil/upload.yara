rule pcloud_storage_user: medium {
  meta:
    description = "uses PCloud for cloud storage"

  strings:
    $pcloud = "api.pcloud.com"

  condition:
    any of them
}

rule google_drive: medium {
  meta:
    ref         = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_high.yar#L1001"
    description = "References known file hosting site"

  strings:
    $d_gdrive = /drive.google.com[\/\?\w\=]{0,64}/

  condition:
    any of ($d_*)
}

rule yandex_disk_user: high {
  meta:
    description = "uses Yandex for cloud storage"

  strings:
    $yandex = "cloud-api.yandex.net/v1/disk"

  condition:
    any of them
}

rule dropbox_disk_user: medium {
  meta:
    description = "uses DropBox for cloud storage"

  strings:
    $dropbox = "dropboxapi.com"
    $Dropbox = "Dropbox"

  condition:
    any of them
}

rule google_drive_uploader: high {
  meta:
    description = "uploads content to Google Drive"

  strings:
    $guploader = "x-guploader-client-info"

  condition:
    any of them
}

rule google_docs_uploader: high {
  meta:
    description = "uploads content to Google Drive"

  strings:
    $writely = "www.google.com/accounts/ServiceLogin?service=writely"

  condition:
    any of them
}

rule file_io_uploader: high {
  meta:
    description = "uploads content to file.io"

  strings:
    $file_io = "file.io" fullword
    $POST    = "POST" fullword
    $Post    = "post" fullword

  condition:
    $file_io and any of ($P*)
}

rule transfer_file: low {
  meta:
    description = "transfers files"

  strings:
    $transfer = "transfer file"

  condition:
    any of them
}

rule upload_file: medium {
  meta:
    description = "uploads files"

  strings:
    $transfer = "upload file"
    $upload2  = /filesUploa[a-z]{0,6}/

  condition:
    any of them
}
