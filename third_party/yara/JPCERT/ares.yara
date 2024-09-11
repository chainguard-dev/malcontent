rule malware_Ares_str {
     meta:
        description = "Ares Python based remote access tool"
        author = "JPCERT/CC Incident Response Group"
        hash = "52550953e6bc748dc4d774fbea66382cc2979580173a7388c01589e8cb882659"
        hash = "123d7abb725bba4e5f9af2f46ff2200d802896fc7b7102c59b1c3a996c48e1b6"
        hash = "f13c5b383710e58dcf6f4a92ed535cc824a77964bdfa358b017aa3dd75e8cb13"

     strings:
        $data1 = "Agent removed successfully" ascii wide
        $data2 = "starting server_hello" ascii wide
        $data3 = "Running python command..." ascii wide
        $data4 = "Creating zip archive..." ascii wide
        $data5 = "Running python file..." ascii wide
        $data6 = "Archive created: %s" ascii wide
        $data7 = "Exiting... (bye!)" ascii wide
        $data8 = "update_consecutive_failed_connections" ascii wide
        $data9 = "get_consecutive_failed_connections" ascii wide
        $data10 = "~/.config/autostart/ares.desktop" ascii wide
        $data11 = "get_install_dir" ascii wide
        $data12 = "command_or_file" ascii wide

     condition:
       5 of ($data*)
}
