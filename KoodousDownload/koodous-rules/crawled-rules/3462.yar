
import "androguard"



 rule YaYaHummingBad2Opt  {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (!) v0.3_summer17"

        original = "1187:HummingBad2"

        date = "24 Aug 2017"


    condition:

        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/Context\;\-\>unregisterReceiver\(Landroid\/content\/BroadcastReceiver\;\)V/) and 

        androguard.functionality.imei.class(/Lcom\/tencent\/bugly\/proguard\/a\;/) and 

        androguard.functionality.imsi.class(/Lcom\/tencent\/bugly\/proguard\/a\;/) and 

        androguard.functionality.imsi.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getSubscriberId\(\)Ljava\/lang\/String\;/) and 

        androguard.functionality.imsi.method(/b/) and 

        androguard.functionality.ssl.method(/e/) and 


        androguard.number_of_permissions == 18 and 


        androguard.url("http://alog.umeng.co/app_logs") and 

        androguard.url("http://alog.umeng.com/app_logs") and 

        androguard.url("http://log.umsns.com/") and 

        androguard.url("http://log.umsns.com/share/api/") and 

        androguard.url("http://oc.umeng.com/check_config_update")

}