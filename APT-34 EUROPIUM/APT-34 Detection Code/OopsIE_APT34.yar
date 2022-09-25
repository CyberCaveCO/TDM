
rule OopsIE_Malware {
   meta:
      description = "OopsIE is a Trojan used by OilRig to remotely execute commands as well as upload/download files to/from victims"
      author = "CyberCave"
      reference = "https://cybercave.com.sa"
      date = "2022-09-24"
      hash1 = "231115a614c99e8ddade4cf4c88472bd3801c5c289595fc068e51b77c2c8563f"
   strings:
      $x1 = "GET / HTTP/1.1 Accept: text/html, application/xhtml+xml, */* Accept-Language: en-US User-Agent: Mozilla/5.0 (Windows NT 6.3; Tri" ascii
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s3 = "dent/7.0; rv:11.0) like Gecko Accept-Encoding: gzip, deflate Proxy-Connection: Keep-Alive Host: %host%" fullword ascii
      $s4 = "IntelSecurityManager.exe" fullword wide
      $s5 = "GET / HTTP/1.1 Accept: text/html, application/xhtml+xml, */* Accept-Language: en-US User-Agent: Mozilla/5.0 (Windows NT 6.3; Tri" ascii
      $s6 = "http://www.msoffice365cdn.com/" fullword wide
      $s7 = "RSchTasks /Create /SC MINUTE /MO 3 /TN \"InetlSecurityAssistManager\" /TR \"%path%\" /f" fullword ascii
      $s8 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s9 = "\\srvCheckresponded.tmp" fullword wide
      $s10 = "MyTemplate" fullword ascii
      $s11 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s12 = "CreateGetStringDelegate" fullword ascii
      $s13 = "Wrong Header Signature" fullword wide
      $s14 = "Unknown Header" fullword wide
      $s15 = "SmartAssembly.Attributes" fullword ascii
      $s16 = "IntelSecurityManager.Resources.resources" fullword ascii
      $s17 = "MemberRefsProxy" fullword ascii
      $s18 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s19 = "IntelSecurityManager.Resources" fullword wide
      $s20 = "6.0.37.15" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}
