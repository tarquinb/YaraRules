
import "androguard"

import "file"

import "cuckoo"



rule Acecard

{

    meta:

        description = "This rule detects acecard families"

        sample = "3c0a9db3f1df04e23c5b8bd711402570a370474853df2541ef187b9997721bc3"


    strings:

        $a = "app_bin/iptables"

        $b = "app_bin/tor"

        $c = "/proc/cpuinfo"

        $d = "ServiceStarter"

        $e = "SDCardServiceStarter"

        $f = "MyDeviceAdminReceiver"

        $g = "MessageReceiver"

        $h = "USSDService"


    condition:

        androguard.filter("android.intent.action.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE") and

        androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 

        5 of them


}