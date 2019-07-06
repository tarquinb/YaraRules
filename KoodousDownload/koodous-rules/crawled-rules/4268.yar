
rule KikDroid {


    strings:

        $s1 = "wss://arab-chat.site"

        $s2 = "wss://chat-messenger.site"

        $s3 = "wss://chat-world.site"

        $s4 = "wss://free-apps.us"

        $s5 = "wss://gserv.mobi"

        $s6 = "wss://kikstore.net"

        $s7 = "wss://network-lab.info"

        $s8 = "wss://onlineclub.info"

        $a1 = "/data/kik.android"

        $a2 = "spydroid"


    condition:


        1 of ($s*) and 1 of ($a*)


}