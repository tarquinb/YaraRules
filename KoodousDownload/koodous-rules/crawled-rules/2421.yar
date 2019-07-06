
rule chrysaor_pegasus {

    meta:

        sample = "ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5"

        description = "https://info.lookout.com/rs/051-ESQ-475/images/lookout-pegasus-android-technical-analysis.pdf"

        author = "A.Sanchez <asanchez@koodous.com>"

    strings:

        $md5_pad = {B6 27 DB 21 5C 7D 35 E4}

        $file_1 = "/upgrade/uglmt.dat"

        $file_2 = "/upgrade/cuvmnr.dat"

        $file_3 = "/upgrade/zero.mp3"

        $d = "pm uninstall com.sec.android.fotaclient"


    condition:

        all of them

}


rule chrysaor_pegasus2 {

    meta:

        sample = "3474625e63d0893fc8f83034e835472d95195254e1e4bdf99153b7c74eb44d86"

        description = "https://info.lookout.com/rs/051-ESQ-475/images/lookout-pegasus-android-technical-analysis.pdf"

        author = "A.Sanchez <asanchez@koodous.com>"

    strings:

        $file_1 = "/mnt/obb/.coldboot_init"

        $library = "libsgn.so"

        $url = "/adinfo?gi=%s&bf=%s"

        $function_1 = "random_hexlified_md5" 

        $function_2 = "get_mac_address"

    condition:

        all of them

}