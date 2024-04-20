rule dev_path : notable {
    meta:
        description = "path reference within /dev"
    strings:
        $path = /\/dev\/[a-z\.\-\/]{1,16}/
        $ignore_null = /\/dev\/nu[l]{1,2}/
        $ignore_shm = "/dev/shm/"
    condition:
        $path and (none of ($ignore*))
}
