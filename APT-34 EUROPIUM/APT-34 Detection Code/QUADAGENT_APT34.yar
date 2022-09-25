

rule QUADAGENT {
   meta:
      description = "QUADAGENT is a PowerShell backdoor the result of using an open-source toolkit called Invoke-Obfuscation"
      author = "CyberCave"
      reference = "https://cybercave.com.sa"
      date = "2022-09-24"
      hash1 = "d948d5b3702e140ef5b9247d26797b6dcdfe4fdb6f367bb217bc6b5fc79df520"
   strings:
      $x1 = "cmd.exe /c powershell -exec bypass -file \"" fullword wide
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s3 = "([System.Net.HttpWebRequest]${R`Eq}).UserAgent = ((\"{16}{36}{32}{13}{10}{12}{17}{33}{28}{29}{3}{24}{18}{35}{34}{7}{19}{5}{14}{2" wide
      $s4 = "SystemDiskClean.exe" fullword wide
      $s5 = "        cmd.exe /c ${Nm`oDU`le}" fullword wide
      $s6 = "${A`Rgs} = '\"'+${fF} + (\"`\" \"+\"\\`\"powershell.exe \"+'') +(((\"{8}{4}{3}{5}{9}{12}{1}{11}{14}{16}{0}{13}{6}{2}{7}{10}{15}" wide
      $s7 = "${V`Al} = Get-ItemProperty -Path (((\"{0}{1}\" -f 'hk','cu:sVN')).REpLaCE('sVN','\\')) -Name ${svnA`mE}" fullword wide
      $s8 = "${T`AsK} =  cmd /c start /b schtasks /query /fo csv | where{${_} -notmatch (\"{2}{1}{0}\"-f 'kNa','as','T')} | findstr ${sV`NaMe" wide
      $s9 = "        ${NmO`DU`le} = ${E`XeCUTa`BLe}+' '+ '\"'+${f`F} + (((\"{2}{3}{0}{4}{1}\" -f 'wersh','l.exe','YTC',' YTCpo','el')) -CrEPL" wide
      $s10 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s11 = "${E`xEc`Utab`lE} = (\"{0}{2}{1}\" -f 'w','cript.exe','s')" fullword wide
      $s12 = "An error occurred while processing your request. code(2343)" fullword wide
      $s13 = "function EAES(${K`eY}, ${bYT`eS}){ ${A`Em} = MA ${k`Ey}; ${eNC`R`YPToR} = ${a`Em}.CreateEncryptor(); ${e`DA`Ta} = ${eNcry`p`ToR}" wide
      $s14 = "    cmd /c start /b schtasks /create /sc minute /mo 5 /tn ${sVNA`me} /tr ${t`R}" fullword wide
      $s15 = "        cmd /c start /b schtasks /delete  /tn ${s`VN`Ame} /f" fullword wide
      $s16 = "if (${K`eY}.getType().Name -eq (\"{2}{0}{1}\" -f 'r','ing','St')) {" fullword wide
      $s17 = "${A`eM}.Key = [System.Convert]::FromBase64String(${k`eY})" fullword wide
      $s18 = "${co`O`KIe} = New-Object System.Net.Cookie((\"{2}{1}{0}\" -f'D','PSESSI','PH'),${co`Okie`Val});" fullword wide
      $s19 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s20 = "{[System.IO.File]::WriteAllText(${FF},(\"CreateObject(`\"WScript.Shell`\").Run \"+\"`\"`\" \"+'& '+'W'+'Script.Arg'+'uments('+'0" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}


