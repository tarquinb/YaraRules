
import "androguard"

import "file"

import "cuckoo"



rule reddrop

{

    meta:

        description = "This rule detects malicious samples belonging to Reddrop campaign"

        sample = "76b2188cbee80fffcc4e3c875e3c9d25"


    strings:

        $a_1 = "assets/payPK"

        $a_2 = "assets/F88YUJ4PK"

        $a_3 = "assets/wyzf/res.binPK"

        $a_4 = "assets/yylist.xmlPK"


    condition:

        androguard.service(/com.y.f.jar.pay.UpdateServices/) and

        androguard.service(/com.wyzfpay.service.CoreService/) and

        androguard.receiver(/com.y.f.jar.pay.InNoticeReceiver/) and

        androguard.receiver(/com.jy.publics.JyProxyReceiver/) and

        all of ($a_*)



}