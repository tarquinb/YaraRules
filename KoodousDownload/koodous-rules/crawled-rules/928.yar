
import "androguard"


rule ggtracker : trojan

{

    meta:

        description = "Android.Ggtracker is a Trojan horse for Android devices that sends SMS messages to a premium-rate number. It may also steal information from the device."

        sample = "8c237092454584d0d6ae458af70dc032445b866fd5913979bbad576f42556577"


    condition:

        androguard.permission(/android.permission.SEND_SMS/) and

        androguard.url("http://ggtrack.org/SM1c?device_id=")

}