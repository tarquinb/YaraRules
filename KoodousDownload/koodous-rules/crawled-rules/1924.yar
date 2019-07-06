
import "androguard"


rule AgentGen : test

{

        meta:

                description = "Artemis Detecti ANDROID/Hiddad.P.Gen "

                sample = "7cf36007b51a319b3d1de2041a57c48a957965c9fe87194a5a7ab3303b50ea74"

        strings:


                $string_1 = "mmAUtjAeH"


        condition:

                $string_1 and

                androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") or

                androguard.url("http://apk-market.net/l2/aacc2ffc4d3e18ef12f908921ad235be")

}