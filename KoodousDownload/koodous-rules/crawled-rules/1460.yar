
import "androguard"

import "file"



rule trojan: pornClicker 

{

    meta:

        description = "Ruleset to detect android pornclicker trojan, connects to a remote host and obtains javascript and a list from urls generated, leading to porn in the end."

        sample = "5a863fe4b141e14ba3d9d0de3a9864c1339b2358386e10ba3b4caec73b5d06ca"

        reference = "https://blog.malwarebytes.org/cybercrime/2016/06/trojan-clickers-gaze-cast-upon-google-play-store/?utm_source=facebook&utm_medium=social"


    strings:

        $a = "SELEN3333"

        $b = "SELEN33"

        $c = "SELEN333"

        $api = "http://mayis24.4tubetv.xyz/dmr/ya"


    condition:

        ($a and $b and $c and $api) or androguard.url(/mayis24\.4tubetv\.xyz/)

}