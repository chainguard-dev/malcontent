import "pe"

rule malware_PSKiller_sys {
    meta:
      description = "detect PSKiller_sys Rook, Atom Silo"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "f807699b6c71382c7d0da61d2becf29d1818483597213f2194bc00e63d47235e"
      hash2 = "c232b3d1ea2273b8ad827724c511d032cda7f2c66567638abf922a5d5287e388"

    strings:
      /* strings */
      $str01 = "hmpalert.exe" fullword ascii
      $str02 = "savservice.exe" fullword ascii
      $str03 = "savadminservice.exe" fullword ascii
      $str04 = "sophoscleanm64.exe" fullword ascii
      $str05 = "sdcservice.exe" fullword ascii
      $str06 = "sophos ui.exe" fullword ascii
      $str07 = "savapi.exe" fullword ascii
      $str08 = "sedservice.exe" fullword ascii
      $str09 = "sspservice.exe" fullword ascii
      $str10 = "sophosfimservice.exe" fullword ascii
      $str11 = "sophosfilescanner.exe" fullword ascii
      $str12 = "sophosfs.exe" fullword ascii
      $str13 = "sophoshealth.exe" fullword ascii
      $str14 = "mcsagent.exe" fullword ascii
      $str15 = "mcsclient.exe" fullword ascii
      $str16 = "sophosntpservice.exe" fullword ascii
      $str17 = "sophossafestore64.exe" fullword ascii
      $str18 = "alsvc.exe" fullword ascii
      $str19 = "swc_service.exe" fullword ascii
      $str20 = "swi_fc.exe" fullword ascii
      $str21 = "swi_filter.exe" fullword ascii
      $str22 = "swi_service.exe" fullword ascii
      $str33 = "vmwp" fullword ascii
      $str34 = "virtualbox" fullword ascii
      $str35 = "vbox" fullword ascii
      $str36 = "sqlservr" fullword ascii
      $str37 = "mysqld" fullword ascii
      $str38 = "omtsreco" fullword ascii
      $str39 = "oracle" fullword ascii
      $str40 = "tnslsnr" fullword ascii
      $str41 = "vmware" fullword ascii
      $str42 = "sql.exe" fullword ascii
      $str43 = "oracle.exe" fullword ascii
      $str44 = "ocssd.exe" fullword ascii
      $str45 = "dbsnmp.exe" fullword ascii
      $str46 = "synctime.exe" fullword ascii
      $str47 = "agntsvc.exe" fullword ascii
      $str48 = "isqlplussvc.exe" fullword ascii
      $str49 = "xfssvccon.exe" fullword ascii
      $str51 = "mydesktopservice.exe" fullword ascii
      $str52 = "ocautoupds.exe" fullword ascii
      $str53 = "encsvc.exe" fullword ascii
      $str54 = "firefox.exe" fullword ascii
      $str55 = "tbirdconfig.exe" fullword ascii
      $str56 = "mydesktopqos.exe" fullword ascii
      $str57 = "ocomm.exe" fullword ascii
      $str58 = "dbeng50.exe" fullword ascii
      $str59 = "sqbcoreservice.exe" fullword ascii
      $str60 = "excel.exe" fullword ascii
      $str61 = "infopath.exe" fullword ascii
      $str62 = "msaccess.exe" fullword ascii
      $str63 = "mspub.exe" fullword ascii
      $str64 = "onenote.exe" fullword ascii
      $str65 = "outlook.exe" fullword ascii
      $str66 = "powerpnt.exe" fullword ascii
      $str67 = "steam.exe" fullword ascii
      $str68 = "thebat.exe" fullword ascii
      $str69 = "thunderbird.exe" fullword ascii
      $str70 = "visio.exe" fullword ascii
      $str71 = "winword.exe" fullword ascii
      $str72 = "wordpad.exe" fullword ascii
      $str73 = "notepad.exe" fullword ascii
      $str74 = "SmcGui.exe" fullword ascii
      $str75 = "SymCorpUI.exe" fullword ascii
      $str76 = "ccSvcHst.exe" fullword ascii
      $str77 = "sepWscSvc64.exe" fullword ascii
      $str78 = "PccNTMon.exe" fullword ascii
      $str79 = "CNTAoSMgr.exe" fullword ascii
      $str80 = "tmsainstance64.exe" fullword ascii
      $str81 = "tmlisten.exe" fullword ascii
      $str82 = "logserver.exe" fullword ascii
      $str83 = "ntrtscan.exe" fullword ascii
      $str84 = "tmccsf.exe" fullword ascii
      $str85 = "supportconnector.exe" fullword ascii
      $str86 = "tmwscsvc.exe" fullword ascii
      $str95 = "macmnsvc.exe" fullword ascii
      $str96 = "macompatsvc.exe" fullword ascii
      $str97 = "masvc.exe" fullword ascii
      $str98 = "mcshield.exe" fullword ascii
      $str99 = "mctray.exe" fullword ascii
      $str100 = "mfeatp.exe" fullword ascii
      $str101 = "mfecanary.exe" fullword ascii
      $str102 = "mfeensppl.exe" fullword ascii
      $str103 = "mfehcs.exe" fullword ascii
      $str104 = "mfemactl.exe" fullword ascii
      $str105 = "mfemms.exe" fullword ascii
      $str106 = "mfetp.exe" fullword ascii
      $str107 = "mfevtps.exe" fullword ascii
      $str108 = "mfewc.exe" fullword ascii
      $str109 = "mfewch.exe" fullword ascii
      $str110 = "mfewch.exe" fullword ascii
      $str111 = "ERAAgent.exe" fullword ascii
      $str112 = "ERAServer.exe" fullword ascii
      $str113 = "RDSensor.exe" fullword ascii
      $str114 = "eguiProxy.exe" fullword ascii
      $str115 = "egui.exe" fullword ascii
      $str116 = "entwine.exe" fullword ascii
      $str117 = "ekrn.exe" fullword ascii
      $str118 = "dsa.exe" fullword ascii
      $str119 = "Notifier.exe" fullword ascii
      $str120 = "coreFrameworkHost.exe" fullword ascii
      $str121 = "coreServiceShell.exe" fullword ascii
      $str122 = "RepUx.exe" fullword ascii
      $str123 = "scanhost.exe" fullword ascii
      $str124 = "RepUtils.exe" fullword ascii
      $str125 = "VHostComms.exe" fullword ascii

    condition:
      (uint16(0) == 0x5A4D)
      and (filesize < 1MB)
      and pe.imports("ntoskrnl.exe", "PsGetProcessId")
      and pe.imports("ntoskrnl.exe", "PsLookupProcessByProcessId")
      and pe.imports("ntoskrnl.exe", "PsGetProcessImageFileName")
      and pe.imports("ntoskrnl.exe", "_stricmp")
      and pe.imports("ntoskrnl.exe", "ZwTerminateProcess")
      and pe.imports("ntoskrnl.exe", "ZwClose")
      and (pe.subsystem == pe.SUBSYSTEM_NATIVE)
      and (3 of ($str*))
}
