rule Adaptix_Beacon
{
    meta:
        id = "1ZkQQJeaX6cNWZ9NA92MVp"
        fingerprint = "v1_sha256_3e65f762c253b42a97dd34e0904aa561b4413685e65b73fc28b2ac326a379722"
        version = "1.0"
        date = "2025-11-20"
        modified = "2025-11-20"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Adaptix beacon."
        category = "MALWARE"
        malware_type = "HACKTOOL"
        tool = "ADAPTIX"
        reference = "https://github.com/Adaptix-Framework/AdaptixC2"

    strings:
        $coffer = "coffer.Load"

        $func_TaskProcess = "main.TaskProcess"
        $func_jobDownloadStart = "main.jobDownloadStart"
        $func_jobRun = "main.jobRun"
        $func_jobTerminal = "main.jobTerminal"
        $func_jobTunnel = "main.jobTunnel"
        $func_taskCat = "main.taskCat"
        $func_taskCd = "main.taskCd"
        $func_taskCp = "main.taskCp"
        $func_taskExecBof = "main.taskExecBof"
        $func_taskExit = "main.taskExit"
        $func_taskJobKill = "main.taskJobKill"
        $func_taskJobList = "main.taskJobList"
        $func_taskKill = "main.taskKill"
        $func_taskLs = "main.taskLs"
        $func_taskMkdir = "main.taskMkdir"
        $func_taskMv = "main.taskMv"
        $func_taskPs = "main.taskPs"
        $func_taskPwd = "main.taskPwd"
        $func_taskRm = "main.taskRm"
        $func_taskScreenshot = "main.taskScreenshot"
        $func_taskShell = "main.taskShell"
        $func_taskTerminalKill = "main.taskTerminalKill"
        $func_taskTunnelKill = "main.taskTunnelKill"
        $func_taskUpload = "main.taskUpload"
        $func_taskZip = "main.taskZip"

    condition:
        ( $coffer and 5 of ($func_*) ) or
        15 of ($func_*)
}
