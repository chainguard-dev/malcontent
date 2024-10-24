rule busybox : override {
  meta:
    description = "busybox"
    infection_killer = "medium"
  strings:
    $description = /BusyBox is a multi-call binary that combines many common Unix\n\tutilities into a single executable./
    $license = "BusyBox is copyrighted by many authors between 1998-2015."
  condition:
    filesize < 1MB and all of them
}
