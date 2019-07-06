
import "androguard"

import "file"

import "cuckoo"



rule ChinesePorn_2

{

    meta:

        description = "This rule detects dirtygirl samples"

        sample = "aeed925b03d24b85700336d4882aeacc"


    condition:

        androguard.receiver(/com.sdky.lyr.zniu.HuntReceive/) and

        androguard.service(/com.sdky.jzp.srvi.DrdSrvi/)


}