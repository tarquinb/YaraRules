
import "androguard"


rule comandroidmediacode

{

    meta:

        description = "This rule detects fraudulent applications based on Umeng"

        sample = "5df9766394428473b790a6664a90cfb02d4a1fd5df494cbedcb01e0d0c02090c"


    strings:

        $a = "ZN2in1cEP7_JNIEnvP8_jobject"

        $b = "PA8)\n"


    condition:

        $a and $b

        and androguard.app_name("com.android.mediacode")



}