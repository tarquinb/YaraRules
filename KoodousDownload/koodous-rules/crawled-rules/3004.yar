
import "androguard"


rule Daemon

{

    meta:

        description = "https://nakedsecurity.sophos.com/2017/06/16/the-google-play-adware-apps-that-just-wont-die/"

        sample = "2C059ED008A549C1AE3B0228B36735487C4CED4E1B60E3888FED9A8F69FD66CA"


    strings:

        $a = "Java_com_marswin89_marsdaemon_nativ_NativeDaemon" nocase


    condition:

        $a


}