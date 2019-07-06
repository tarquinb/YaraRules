
import "androguard"



rule shuanet : adWare

{

    meta:

        description = "This rule detects shuanet aggresive malware"


    condition:

        androguard.service(/com\/boyaa\/push/) and

        androguard.receiver(/orp\/frame\/shuanet\/abs/)



}


rule shuanet2 : adWare

{

    meta:

        description = "This rule detects shuanet aggresive malware"


    condition:

        androguard.service("com/boyaa/push/NotifyCenterAIDL") and

        androguard.receiver("orp/frame/shuanet/abs/DataReciver")


}