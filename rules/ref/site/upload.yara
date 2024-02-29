rule pcloud_storage_user : notable {
  meta:
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2022_CloudMensis_mdworker3 = "273633eee4776aef40904124ed1722a0793e6567f3009cdb037ed0a9d79c1b0b"
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
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
  meta:
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
  strings:
    $yandex = "cloud-api.yandex.net/v1/disk"
  condition:
    any of them
}

rule dropbox_disk_user : notable {
  meta:
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
  strings:
    $dropbox = "dropboxapi.com"
  condition:
    any of them
}

rule google_drive_uploader : suspicious {
  meta:
	description = "Uploads content to Google Drive"
  strings:
    $guploader = "x-guploader-client-info"
  condition:
    any of them
}

rule google_docs_uploader : suspicious {
  meta:
	description = "Uploads content to Google Drive"
  strings:
    $writely = "www.google.com/accounts/ServiceLogin?service=writely"
  condition:
    any of them
}
