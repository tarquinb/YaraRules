
import "cuckoo"



rule Umeng

{

    meta:

        description = "Evidences of Umeng advertisement library / Adware "


    condition:

        cuckoo.network.dns_lookup(/alog.umeng.com/) or cuckoo.network.dns_lookup(/oc.umeng.com/)


}