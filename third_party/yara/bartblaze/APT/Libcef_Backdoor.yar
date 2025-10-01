rule Libcef_Backdoor
{
    meta:
        id = "2kQ17alOYwTwkkTNA8vZCX"
        fingerprint = "v1_sha256_7a32b90fb6e962a82af808d698dc19d503c075606f5a7e52f783f0c7d71f5936"
        version = "2.0"
        date = "2025-09-26"
        modified = "2025-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies backdoored libcef.dll, used by an unknown (likely) APT. Uses Telegram for exfil."
        category = "MALWARE"
        malware = "UNKNOWN"
        malware_type = "BACKDOOR"
        reference = "https://github.com/bartblaze/Yara-rules"
        hash = "a3805b24b66646c0cf7ca9abad502fe15b33b53e56a04489cfb64a238616a7bf"

    strings:
        $s1 = "Could not get process list."
        $s2 = "Please send the document now." 
        $s3 = "Failed to create pipe." 
        $s4 = "Failed to start process." 
        $s5 = "Command executed but returned no output." 
		$s6 = "Screenshot taken."
		$s7 = "Please send a document, not text."

        $x1 = "No file or photo found in message."
        $x2 = "Error: Cannot create file on disk."
        $x3 = "File saved to: "
        $x4 = "Error receiving file:"
		
    condition:
        4 of ($s*) or 3 of ($x*)
}
