
import "androguard"




rule Lockscreen : malware

{

    meta:

        description = "https://www.symantec.com/security_response/writeup.jsp?docid=2015-032409-0743-99&tabid=2"



    condition:


        androguard.service(/lockphone.killserve/i) and

        androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and

        androguard.filter(/android.intent.action.BOOT_COMPLETED/)



}