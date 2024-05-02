rule bincapz_path : harmless {
    meta:
        description = "path reference containing bincapz binary"
    strings:
        $path = "bincapz"
    condition:
        none of them
}
