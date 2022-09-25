
rule SideTwist_backdoor {
   meta:
      description = "SideTwist is a C-based backdoor that has been used by OilRig since at least 2021"
      author = "CyberCave"
      reference = "https://cybercave.com.sa"
      date = "2022-09-23"
      hash1 = "47d3e6c389cfdbc9cf7eb61f3051c9f4e50e30cf2d97499144e023ae87d68d5a"
   strings:
      $x1 = "c:\\windows\\system32\\cmd.exe" fullword wide
      $s2 = "D:\\Projects\\Gustavo\\Client\\Release\\SystemIdle.pdb" fullword ascii
      $s3 = "sarmsoftware.com" fullword wide
      $s4 = ".\\start.exe" fullword wide
      $s5 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" fullword wide
      $s6 = " Type Descriptor'" fullword ascii
      $s7 = "error_%s|Error: %d" fullword wide
      $s8 = "Bapi-ms-win-appmodel-runtime-l1-1-1" fullword wide
      $s9 = "Gustavo, Version 1.0" fullword wide
      $s10 = "GUSTAVO" fullword wide
      $s11 = " Class Hierarchy Descriptor'" fullword ascii
      $s12 = " Base Class Descriptor at (" fullword ascii
      $s13 = "b<log10" fullword ascii
      $s14 = "Gustavo" fullword wide
      $s15 = " Complete Object Locator'" fullword ascii
      $s16 = "Badvapi32" fullword wide
      $s17 = "APPDATA" fullword wide /* Goodware String - occured 93 times */
      $s18 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
      $s19 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
      $s20 = "network down" fullword ascii /* Goodware String - occured 567 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

