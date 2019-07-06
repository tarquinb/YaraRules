
import "androguard"



rule koler : ransomware

{

    meta:

        description = "Koler Ransomware"

        sample = "b79916cb44be7e1312d84126cb4f03781b038d10"

        source = "https://www.bleepingcomputer.com/news/security/koler-android-ransomware-targets-the-us-with-fake-pornhub-apps/"


    strings:

        $fbi_1 = "FEDERAL BUREAU OF INVESTIGATION" nocase

        $fbi_2 = "FBI HEADQUARTER" nocase

        $porn = "child pornography" nocase


    condition:

        all of ($fbi_*)

        and $porn

        and androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)

}