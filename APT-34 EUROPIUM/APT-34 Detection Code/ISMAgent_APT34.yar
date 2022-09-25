
rule ISMAgent_C2 {
   meta:
      description = "ISMAgent falls back to its DNS tunneling mechanism if it is unable to reach the C2 server over HTTP"
      author = "CyberCave"
      reference = "https://cybercave.com.sa"
      date = "2022-09-22"
      hash1 = "33c187cfd9e3b68c3089c27ac64a519ccc951ccb3c74d75179c520f54f11f647"
   strings:
      $s1 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\RegAsm.exe" fullword wide
      $s2 = "PolicyConverter.exe" fullword wide
      $s3 = "SrvHealth.exe" fullword wide
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s5 = "srvBS.txt" fullword wide
      $s6 = "{a3538ba3-5cf7-43f0-bc0e-9b53a98e1643}, PublicKeyToken=3e56350693f7355e" fullword wide
      $s7 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s8 = "MyTemplate" fullword ascii
      $s9 = "Wrong Header Signature" fullword wide
      $s10 = "Unknown Header" fullword wide
      $s11 = "SmartAssembly.Attributes" fullword ascii
      $s12 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s13 = "PolicyConverter.Resources" fullword wide
      $s14 = "#Powered by SmartAssembly 6.10.0.218" fullword ascii
      $s15 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s16 = "AuthenticationMode" fullword ascii /* Goodware String - occured 32 times */
      $s17 = "CreateDecryptor" fullword ascii /* Goodware String - occured 76 times */
      $s18 = "Tsk2" fullword ascii 
      $s19 = "LoadFile" fullword ascii /* Goodware String - occured 101 times */
      $s20 = "srvBS.txt" fullword ascii 
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

