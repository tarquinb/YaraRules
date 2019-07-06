
import "androguard"


rule Banker1 {

    strings:

        $ = "MessageReceiver"

        $ = "AlarmReceiver"

        $ = "BootReceiver"

        $ = "AdminRightsReceiver"

        $ = "AdminService"

        $ = "FDService"

        $ = "USSDService"

        $ = "MainService"


    condition:

        all of them


}


rule Banker2 {

    strings:

        $ = "85.93.5.228/index.php?action=command"

        $ = "email@fgdf.er"

        $ = "majskdd@ffsa.com"

        $ = "185.48.56.10"

    condition:

        1 of them

}




rule Zitmo

{

    meta:

        description = "Trojan-Banker.AndroidOS.Zitmo"

        sample = "c0dde72ea2a2db61ae56654c7c9a570a8052182ec6cc9697f3415a012b8e7c1f"


    condition:

        androguard.receiver("com.security.service.receiver.SmsReceiver") and

        androguard.receiver("com.security.service.receiver.RebootReceiver") and

        androguard.receiver("com.security.service.receiver.ActionReceiver")


}


rule Banker3

{

    strings:

    $ = "cosmetiq/fl/service" nocase


    condition:

    1 of them


}