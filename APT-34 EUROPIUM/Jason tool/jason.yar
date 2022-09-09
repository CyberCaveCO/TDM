rule _APT34_Jason {
   meta:
      description = "APT34 Jason"
      date = "2019-06-05"
      hash1 = 
"9762444b94fa6cc5a25c79c487bbf97e007cb680118afeab0f5643d211fa3f78"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, 
Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "D:\\Project\\Jason\\obj\\Release\\Jason.pdb" fullword ascii
      $s3 = "Jason.exe" fullword wide
      $s4 = "get_PasswordPattern" fullword ascii
      $s5 = "get_PasswordFile" fullword ascii
      $s6 = "get_pCurrentPassword" fullword ascii
      $s7 = "Microsoft.Exchange.WebServices.Data" fullword ascii
      $s8 = "Total Login Successful :" fullword wide
      $s9 = "Login Successful" fullword wide
      $s10 = "<PasswordPattern>k__BackingField" fullword ascii
      $s11 = "<pCurrentPassword>k__BackingField" fullword ascii
      $s12 = "Jason - Exchange Mail BF - v 7.0" fullword wide
      $s13 = "Please enter Password File" fullword wide
      $s14 = "get_UsernameStart" fullword ascii
      $s15 = "get_UserPassFile" fullword ascii
      $s16 = "get_pCurrentUsername" fullword ascii
      $s17 = "set_pCurrentPassword" fullword ascii
      $s18 = "set_PasswordFile" fullword ascii
      $s19 = "set_PasswordPattern" fullword ascii
      $s20 = "connection was closed" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}
