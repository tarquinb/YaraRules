
rule packers : apkprotect

{

    meta:

        description = "This rule detects packers based on files used by them"



    strings:

        $apkprotect_1 = ".apk@"

        $apkprotect_2 = "libAPKProtect"


    condition:

        2 of them


}