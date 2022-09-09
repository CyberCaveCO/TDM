rule ZeroCleare_PS1 : APT
{
    meta:
        author = "PolySwarm"
        date = "07-01-2020"

    strings:
        $filename = "ClientUpdate.ps1"
        $deckey = "DECKey"
        $var = "ContentData"
        $params = "SilentlyContinue"
        $sleep = "Start-Sleep 5"
        $decrypt_fnc = "Decrypte-Content"
        $base64_data = "$ClientData"
        // can be payload specific
        $payload = "gidhUoEOr4Kr+F9le1lZZk1Ll6OxRxKlOgFsa2ZlyhpEIc1bqsvNSskTc4ifiNqKZ3QI38MFCNrRvgU0d2ASasAhW53Pl58vty+IHa8hmlQnUmFa7eT9kqJcpYS43htJ1vm"

    condition:
        all of them
}