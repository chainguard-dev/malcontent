rule buildah_dev_shm: override {
  meta:
    description    = "buildah"
    dev_shm_hidden = "high"

  strings:
    $buildah = /[Bb]uildah/
    $repo    = "github.com/containers/buildah"

  condition:
    filesize < 40MB and #buildah > 2000 and $repo
}
