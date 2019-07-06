
import "androguard"


rule fbilocker {

    strings:    

        $a1 = "comdcompdebug.500mb.net/api33"

        $a2 = "itsecurityteamsinc.su"

        $a3 = "api.php"

    condition:

        androguard.certificate.sha1("A4DF11815AF385578CEC757700A3D1A0AF2136A8") or

        2 of ($a*)

}