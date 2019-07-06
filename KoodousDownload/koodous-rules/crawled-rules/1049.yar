
import "androguard"

import "file"

import "cuckoo"



rule rootnik : sites

{

    meta:

        description = "sites created as of Feb 2015"

        sample = "17a00e9e8a50a4e2ae0a2a5c88be0769a16c3fc90903dd1cf4f5b0b9b0aa1139"


    condition:

        cuckoo.network.http_request(/http:\/\/applight\.mobi/) and      cuckoo.network.http_request(/http:\/\/jaxfire\.mobi/)  and cuckoo.network.http_request(/http:\/\/superflashlight\.mobi/) and        cuckoo.network.http_request(/http:\/\/shenmeapp\.mobi/)



}


rule rootnik2 : sites2

{


    strings:

     $a = "aHR0cDovL2Nkbi5hcHBsaWdodC5tb2JpL2FwcGxpZ2h0LzIwMTUvMTQ0MjgyNDQ2MnJlcy5iaW4=" // base 64 encoded: /http:\/\/cdn.applight.mobi\/applight\/2015\/1442824462res.bin/

    condition:

         cuckoo.network.http_request(/http:\/\/api.jaxfire\.mobi\/app\/getTabsResBin/) and (cuckoo.network.http_request(/http:\/\/cdn.applight.mobi\/applight\/2015\/1442824462res.bin/) or $a)


}

rule rootnik3 : string

{

    strings:

    $a = "http://api.shenmeapp.info/info/report"

    condition:

    $a or (androguard.url(/applight\.mobi/) and androguard.url(/jaxfire\.mobi/))

}


rule rooting {

    meta:

        sample = "7fce9e19534b0a0590c7383c7180b9239af3ad080e0df9d42b0493bb6e0e0ef7" // SHA256

    strings: 

    $a= "http://api01.app001.cn/action/init_dev.php"

$b = "http://api02.app001.cn/action/check_auto_upgrade.php"

$c = "http://api02.app001.cn/action/check_connect.php"

$d = "http://api02.app001.cn/action/check_push.php"

$e = "http://api02.app001.cn/action/get_rooting_app.php"

    condition: 

    $a or $b or $c or $d or $e

}