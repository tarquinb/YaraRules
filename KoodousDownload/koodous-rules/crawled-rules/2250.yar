
rule RootNik {

    meta:

    description = "https://blog.fortinet.com/2017/01/26/deep-analysis-of-android-rootnik-malware-using-advanced-anti-debug-and-anti-hook-part-ii-analysis-of-the-scope-of-java"


    strings:


        $ = "grs.gowdsy.com"

        $ = "gt.rogsob.com"

        $ = "gt.yepodjr.com"

        $ = "qj.hoyebs.com"

        $ = "qj.hoyow.com"


    condition:

        1 of them


}