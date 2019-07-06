
import "androguard"



rule svpeng

{

    meta:

        description = "Trojan-Banker.AndroidOS.Svpeng"

        sample = "62aaff01aef5b67637676d79e8ec40294b15d6887d9bce01b11c6ba687419302"


    condition:

        androguard.receiver("com.up.net.PoPoPo") or

        androguard.receiver("com.up.net.PusyCat")


}


rule svpeng2

{

    strings:

        $= "http://217.182.174.92/jack.zip"

    condition:

        all of them

}