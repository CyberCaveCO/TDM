
rule APT34__Karkoff {
   meta:
      description = "A malware designed to execute code remotely on compromised hosts"
      author = "CyberCave"
      reference = "https://cybercave.com.sa"
      date = "2022-09-23"
      hash1 = "5b102bf4d997688268bab45336cead7cdf188eb0d6355764e53b4f62e1cdf30c"
   strings:
      $s1 = "DropperBackdoor.Newtonsoft.Json.dll" fullword wide
      $s2 = "C:\\Windows\\Temp\\MSEx_log.txt" fullword wide
      $s3 = "CMD.exe" fullword wide
      $s4 = "DropperBackdoor.exe" fullword wide
      $s5 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s6 = "rimrun.com" fullword wide
      $s7 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.get_I" ascii
      $s8 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.get_C" ascii
      $s9 = "get_ProcessExtensionDataNames" fullword ascii
      $s10 = "get_ProcessDictionaryKeys" fullword ascii
      $s11 = "System.Runtime.CompilerServices.IsByRefLikeAttribute" fullword wide
      $s12 = "BSON reading and writing has been moved to its own package. See https://www.nuget.org/packages/Newtonsoft.Json.Bson for more det" ascii
      $s13 = "BSON reading and writing has been moved to its own package. See https://www.nuget.org/packages/Newtonsoft.Json.Bson for more det" ascii
      $s14 = "System.Collections.Generic.IEnumerator<System.Collections.Generic.KeyValuePair<System.Object,System.Object>>.get_Current" fullword ascii
      $s15 = "uJSON Schema validation has been moved to its own package. See https://www.newtonsoft.com/jsonschema for more details." fullword ascii
      $s16 = " https://www.newtonsoft.com/json 0" fullword ascii
      $s17 = "System.ComponentModel.ComponentConverter" fullword wide
      $s18 = "System.ComponentModel.ReferenceConverter" fullword wide
      $s19 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.Conta" ascii
      $s20 = "System.Collections.Generic.ICollection<System.Collections.Generic.KeyValuePair<System.String,Newtonsoft.Json.Linq.JToken>>.CopyT" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

