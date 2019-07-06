
import "androguard"


rule smsreg

{

    meta:

        sample = "1c2e1083f9c73a222af21351b243d5072fcc3360a5be6fa4d874e4a94249a68d"

        search = "package_name:com.dnstore.vn"


    strings:

        //$url1 = "http://bitly.com/360Riverads"

        //$url2 = "http://bitly.com/UCriverads"

        $a = "var msg2_4 = \"DSD zombie\";"

        //$url3 = "http://bitly.com/apuslaunchereway"

        $b = "Ldnteam/gamevui2014/net/ScriptInterface$Downloader3"


    condition:

        ($a and $b) or androguard.package_name("com.dnstore.vn")


}