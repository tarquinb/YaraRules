
import "androguard"


rule koodous : official

{

    meta:

        description = "Ruleset to detect Exaspy RAT"

        sample = "0b8eb5b517a5a841a888d583e0a187983c6028b92634116cfc9bf79d165ac988"


    strings:

        $a = "Sending log to the server. Title: %s Severity: %s Description: %s Module: %s"

        $b = "KEY_LICENSE"

        $c = "Failed to install app in system partition.\n"

        $d = "key_remote_jid"


    condition:

        androguard.url("http://www.exaspy.com/a.apk") or androguard.url("http://api.andr0idservices.com") or all of them


}