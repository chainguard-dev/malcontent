private rule dev_null {
    strings:
        $path = "/dev/null"
    condition:
        $path
}

private rule dev_shm {
    strings:
        $path = /\/dev\/shm\/.*/
    condition:
        $path
}

rule dev_path : notable {
    meta:
        description = "path reference within /dev"
    strings:
        $path = /\/dev\/[a-z\.\-\/]+/
    condition:
        $path and not dev_null and not dev_shm
}
