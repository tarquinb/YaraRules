
rule smssend

{

    meta:

        description = "This rule detects smssend trojan"

        sample = "fcfe5c16b96345c0437418565dbf9c09e9e97c266c48a3b04c8b947a80a6e6c3"


    strings:

        $a = "generatesecond"

        $b = "res/layout/notification_download_finished.xml"

        $c = "m_daemonservice"

        $d = "((C)NokiaE5-00/SymbianOS/9.1 Series60/3.0"

        $e = "respack.tar"


    condition:

        all of them



}