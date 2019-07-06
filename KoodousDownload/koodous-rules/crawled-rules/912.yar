
import "androguard"




rule koodous : official

{

    meta:

        description = "Ads and pron. Gets to remote host(porn) http://hwmid.ugameok.hk:8803/vvd/"


    strings:

        $a = "http://hwmid.ugameok.hk:8803/vvd/main?key="


    condition:

        androguard.certificate.sha1("C2:E4:C2:C7:AA:E9:ED:9C:C9:4B:B0:12:BA:DB:52:26:D1:27:87:42") or $a


}