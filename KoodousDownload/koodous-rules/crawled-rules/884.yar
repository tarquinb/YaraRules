
import "androguard"




rule rusSMSfraud

{

    meta:

        description = "russian porn fraud. tricks the user into a cordova app"


    strings:

        $a = "file:///android_asset/html/end.html"

        $b = "file:///android_asset/html/index.html"

        $c = "sendSms2(): "

    condition:

        all of them


}