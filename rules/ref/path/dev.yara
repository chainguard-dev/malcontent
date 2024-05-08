
rule dev_path : medium {
  meta:
    description = "path reference within /dev"
    hash_2023_Downloads_039e = "039e1765de1cdec65ad5e49266ab794f8e5642adb0bdeb78d8c0b77e8b34ae09"
    hash_2023_Downloads_06ab = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
    hash_2024_Downloads_384e = "384ec732200ab95c94c202f42b51e870f51735768888aaabc4e370de74e825e3"
  strings:
    $path = /\/dev\/[\w\.\-\/]{1,16}/
    $ignore_null = "/dev/null"
    $ignore_shm = "/dev/shm/"
  condition:
    $path and none of ($ignore*)
}
