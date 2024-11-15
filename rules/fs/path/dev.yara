rule dev_path: medium {
  meta:
    description = "path reference within /dev"

  strings:
    $path        = /\/dev\/[\w\.\-\/]{1,16}/
    $ignore_null = "/dev/null"
    $ignore_shm  = "/dev/shm/"

  condition:
    $path and none of ($ignore*)
}
