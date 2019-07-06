
import "androguard"


rule limeUrls

{

    meta:

        description = "Ruleset containing c&c servers used by the Lime trojan." 


    strings:

        $site1 = "limeox.ru" 

        $site2 = "3amutka.ru"

        $site3 = "11.serj1228.aux.su"

        $site4 = "185.87.193.242" 

        $site5 = "driver-free.biz" 

        $site6 = "gbb1.ru"

        $site7 = "95.183.13.146"

        $site8 = "jolit.ga"

        $site9 = "g.xenon.myjino.ru"

        $site10 = "trino.myjino.ru"

        $site11 = "amigolite.ru"

        $site12 = "admin25.tw1.su"

        $site13 = "wertik-dok2.myjino.ru"

        $site14 = "deram.myjino.ru"

        $site15 = "44448888.ru" 

        $site16 = "http://ltnari3g.beget.tech/"


    condition:

        any of them or (androguard.activity("app.six.AdmActivity") and androguard.activity("app.six.CardAtivity") and androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED"))  

}