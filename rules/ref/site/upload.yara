
rule pcloud_storage_user : notable {
  strings:
    $pcloud = "api.pcloud.com"
  condition:
    any of them
}

rule google_drive : notable {
  meta:
    ref = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_suspicious.yar#L1001"
    description = "References known file hosting site"
  strings:
    $d_gdrive = /drive.google.com[\/\?\w\=]{0,64}/
  condition:
    any of ($d_*)
}

rule yandex_disk_user : suspicious {
  strings:
    $yandex = "cloud-api.yandex.net/v1/disk"
  condition:
    any of them
}

rule dropbox_disk_user : notable {
  strings:
    $dropbox = "dropboxapi.com"
  condition:
    any of them
}

rule google_drive_uploader : suspicious {
  meta:
    description = "uploads content to Google Drive"
  strings:
    $guploader = "x-guploader-client-info"
  condition:
    any of them
}

rule google_docs_uploader : suspicious {
  meta:
    description = "uploads content to Google Drive"
  strings:
    $writely = "www.google.com/accounts/ServiceLogin?service=writely"
  condition:
    any of them
}
