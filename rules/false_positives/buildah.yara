rule buildah_dev_shm: override {
  meta:
    description    = "buildah"
    dev_shm_hidden = "low"

  strings:
    $buildah = /[Bb]uildah/
    $dev_shm = "/dev/shm/.rootfs"
    $repo    = "github.com/containers/buildah"

  condition:
    filesize < 40MB and #buildah > 2000 and $dev_shm and $repo
}
