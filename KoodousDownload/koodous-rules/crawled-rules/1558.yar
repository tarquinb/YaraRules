
rule PinguLocker

{

    meta:

        description = "This rule detects a locker for Android"

        sample = "aa0b52f66982a0d22d724ee034d0a36296f1efb452e9a430bd23edbc9741b634"


    strings:

        $a = "res/anim/tvanim.xmlPK"

        $b = "access$L1000001"

        $c = "access$L1000002"

        $d = "res/layout/newone.xmlPK"

        $e = "Created-By: 1.0 (Android SignApk)"


    condition:

        all of them


}