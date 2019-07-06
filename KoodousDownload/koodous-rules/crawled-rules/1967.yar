
import "androguard"


rule Android_GMBot_Variant

{

    meta:

        author = "Jacob Soo Lead Re"

        date = "08-November-2016"

        description = "This rule will be able to tag all GMBot variants."

        source = ""

    condition:

        androguard.service(/\.HeadlessSmsSendService/i) and

        androguard.receiver(/\.PushServiceRcvr/i) and

        androguard.receiver(/\.MmsRcvr/i) and

        androguard.receiver(/\.BootReceiver/i)

}