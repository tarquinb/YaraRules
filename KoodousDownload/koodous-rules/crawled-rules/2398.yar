
import "androguard"



rule ransomware

{

    meta:

        description = "This rule detects Russian ransomware (also in AndroidTV)"

        sample = "7fcf3fb097fe347b30bb7011ebb415bb43711a2a8ffde97824528b62a6fdcebd "

        source = "https://www.zscaler.com/blogs/research/new-android-ransomware-bypasses-all-antivirus-programs?utm_source=Social-media&utm_medium=twitter&utm_content=007v94o87z0zb90&utm_campaign=Q3Y17+Blog&utm_ID=UI"


    strings:

        $a = "VISA QIWI WALLET" wide ascii


    condition:

        (androguard.package_name("ru.ok.android") or

        androguard.package_name("com.nitroxenon.terrarium") or

        androguard.package_name("com.cyanogenmod.eleven"))

        and $a


}