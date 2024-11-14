rule emscripten: override {
  meta:
    description                  = "emscripten.sh"
    tool_chmod_relative_run_tiny = "medium"

  strings:
    $license = "Copyright 2017 The Rust Project Developers."
    $script  = "emscripten"
    $sdk     = "emsdk"

  condition:
    filesize < 2KB and all of them
}

rule linux_s390x: override {
  meta:
    description                  = "linux-s390x.sh"
    tool_chmod_relative_run_tiny = "medium"

  strings:
    $img    = "https://github.com/qemu/qemu/raw/master/pc-bios/s390-ccw.img"
    $initrd = "http://ftp.debian.org/debian/dists/testing/main/installer-s390x/20170828/images/generic/initrd.debian"
    $kernel = "http://ftp.debian.org/debian/dists/testing/main/installer-s390x/20170828/images/generic/kernel.debian"

  condition:
    filesize < 1024 and all of them
}

rule linux_sparc64: override {
  meta:
    description                  = "linux-sparc64.sh"
    tool_chmod_relative_run_tiny = "medium"

  strings:
    $iso    = "https://cdimage.debian.org/cdimage/ports/9.0/sparc64/iso-cd/debian-9.0-sparc64-NETINST-1.iso"
    $initrd = "debian-9.0-sparc64-NETINST-1.iso boot/initrd.gz"
    $kernel = "debian-9.0-sparc64-NETINST-1.iso boot/sparc64"

  condition:
    filesize < 1024 and all of them
}
