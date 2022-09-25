
rule Helminth_APT34  {
   meta:
      description = "Helminth  is a backdoor that has at least two variants - one written in VBScript and PowerShell that is delivered via a macros in Excel spreadsheets"
      author = "CyberCave"
      reference = "https://cybercave.com.sa"
      date = "2022-09-22"
      hash1 = "662c53e69b66d62a4822e666031fd441bbdfa741e20d4511c6741ec3cb02475f"
   strings:
      
      $x1 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {(Get-Content $env:Public\\Libraries\\update.vbs) -replace '__',(Get-Random) | Set-C" ascii
      $x2 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii
      $x3 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii
      $s4 = "' $f;(Get-Content $env:Public\\Libraries\\update.vbs) -replace '__',(Get-Random) | Set-Content $env:Public\\Libraries\\update.vb" wide
      $s5 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide
      $s6 = "wss.Run \"http://www.stcs.com.sa/portal.php?lang=1&p=6:88\"" fullword ascii
      $s7 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide
      $s8 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {waitfor haha /T 2}\" & Chr(34), 0" fullword ascii
      $s9 = "eyR3Yz0obmV3LW9iamVjdCBTeXN0ZW0uTmV0LldlYkNsaWVudCk7d2hpbGUoMSl7dHJ5eyRyPUdldC1SYW5kb207JHdjLkRvd25sb2FkRmlsZSgnIiZTRVJWRVImIi1f" ascii /* base64 encoded string '{$wc=(new-object System.Net.WebClient);while(1){try{$r=Get-Random;$wc.DownloadFile('"&SERVER&"-_' */
      $s10 = "YWRFeGVjdXRlPSJwb3dlcnNoZWxsICIiJnskcj1HZXQtUmFuZG9tOyR3Yz0obmV3LW9iamVjdCBTeXN0ZW0uTmV0LldlYkNsaWVudCk7JHdjLkRvd25sb2FkRmlsZSgn" ascii /* base64 encoded string 'adExecute="powershell ""&{$r=Get-Random;$wc=(new-object System.Net.WebClient);$wc.DownloadFile('' */
      $s11 = "    cmd = \"powershell \"\"&{$f=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('\" & StreamName & \"'" ascii
      $s12 = "C:\\Windows\\system32\\stdole2.tlb" fullword ascii
      $s13 = "c2l0aW9uJ10uU3Vic3RyaW5nKCR3Yy5SZXNwb25zZUhlYWRlcnNbJ0NvbnRlbnQtRGlzcG9zaXRpb24nXS5JbmRleE9mKCdmaWxlbmFtZT0nKSs5KSsnLnR4dCcpO0dl" ascii /* base64 encoded string 'sition'].Substring($wc.ResponseHeaders['Content-Disposition'].IndexOf('filename=')+9)+'.txt');Ge' */
      $s14 = "KyRyKyctXycpO1JlbmFtZS1JdGVtIC1wYXRoICgnIiZIT01FJiJ1cFwnKyRyKyctXycpIC1uZXduYW1lICgkd2MuUmVzcG9uc2VIZWFkZXJzWydDb250ZW50LURpc3Bv" ascii /* base64 encoded string '+$r+'-_');Rename-Item -path ('"&HOME&"up\'+$r+'-_') -newname ($wc.ResponseHeaders['Content-Dispo' */
      $s15 = "Jm09ZCcsJyImSE9NRSYiZG5cJyskcisnLi1fJyk7UmVuYW1lLUl0ZW0gLXBhdGggKCciJkhPTUUmImRuXCcrJHIrJy4tXycpIC1uZXduYW1lICgkd2MuUmVzcG9uc2VI" ascii /* base64 encoded string '&m=d','"&HOME&"dn\'+$r+'.-_');Rename-Item -path ('"&HOME&"dn\'+$r+'.-_') -newname ($wc.ResponseH' */
      $s16 = "C:\\Program Files\\Microsoft Office\\Office16\\EXCEL.EXE" fullword ascii
      $s17 = "IiZTRVJWRVImIi1fJm09ZCcsJyImSE9NRSYiZG5cJyskcisnLi1fJyk7SW52b2tlLUV4cHJlc3Npb24gKCciJkhPTUUmImRuXCcrJHIrJy4tXyA+IiZIT01FJiJ1cFwn" ascii /* base64 encoded string '"&SERVER&"-_&m=d','"&HOME&"dn\'+$r+'.-_');Invoke-Expression ('"&HOME&"dn\'+$r+'.-_ >"&HOME&"up\'' */
      $s18 = "ZWFkZXJzWydDb250ZW50LURpc3Bvc2l0aW9uJ10uU3Vic3RyaW5nKCR3Yy5SZXNwb25zZUhlYWRlcnNbJ0NvbnRlbnQtRGlzcG9zaXRpb24nXS5JbmRleE9mKCdmaWxl" ascii /* base64 encoded string 'eaders['Content-Disposition'].Substring($wc.ResponseHeaders['Content-Disposition'].IndexOf('file' */
      $s19 = "bGUoJyImU0VSVkVSJiJ1cGwmbT11JywkXy5GdWxsTmFtZSl9O1JlbW92ZS1JdGVtICRfLkZ1bGxOYW1lfTtSZW1vdmUtSXRlbSAoJyImSE9NRSYiZG5cJyskcisnLi1f" ascii /* base64 encoded string 'le('"&SERVER&"upl&m=u',$_.FullName)};Remove-Item $_.FullName};Remove-Item ('"&HOME&"dn\'+$r+'.-_' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 200KB and
      1 of ($x*) and 4 of them
}

