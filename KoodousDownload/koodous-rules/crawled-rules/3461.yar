
import "androguard"



 rule YaYaSyringeOpt1 {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (!) v0.3_summer17"

        date = "24 Aug 2017"

        original = "1154:Syringe"


    condition:

        androguard.app_name("Super Video Downloader") and 


        androguard.certificate.sha1("816199E3E7DB93A8ABF0B01D24271AF43D6D240F") and 


        androguard.displayed_version("1.0") and 


        androguard.functionality.crypto.code(/invoke\-virtual\ v1\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\)\[B/) and 

        androguard.functionality.socket.class(/Lcom\/aqplay\/shell\/i\;/) and 

        androguard.functionality.socket.method(/j/) and 

        androguard.functionality.ssl.code(/const\-string\ v3\,\ \'https\:\/\/m\.youtube\.com\/watch\?v\=\'/) and 

        androguard.functionality.ssl.method(/onClick/) and 


        androguard.number_of_filters == 14 and 


        androguard.number_of_permissions == 11 and 


        androguard.number_of_providers == 2 and 


        androguard.url("vnd.android.cursor.dir/com.umeng.dl") and 

        androguard.url("vnd.android.cursor.item/com.demo.history") and 

        androguard.url("vnd.android.cursor.dir/com.umeng.dl")

}



rule YaYaSyringeOpt2 {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (!) v0.3_summer17"

        date = "24 Aug 2017"

        original = "1154:Syringe"


    condition:

        androguard.app_name("Alarm Controller") and 


        androguard.certificate.sha1("22B253E10FEDB833435E2CC213F68B29FCBA3AB1") and 


        androguard.functionality.crypto.code(/invoke\-virtual\ v1\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\)\[B/) and 

        androguard.functionality.crypto.method(/a/) and 

        androguard.functionality.socket.code(/invoke\-virtual\ v0\,\ Ljava\/net\/URL\;\-\>openConnection\(\)Ljava\/net\/URLConnection\;/) and 

        androguard.functionality.socket.code(/invoke\-virtual\ v4\,\ Ljava\/net\/URL\;\-\>openConnection\(\)Ljava\/net\/URLConnection\;/) and 


        androguard.number_of_filters == 10 and 


        androguard.number_of_permissions == 15 and 


        androguard.number_of_receivers == 2 and 


        androguard.number_of_services == 3 and 


        androguard.package_name("com.al.alarm.controller") and 


        androguard.url("http://s.adslinkup.com/v2/ads/update/")

}


rule YaYaSyringeOpt3 {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (!) v0.3_summer17"

        date = "24 Aug 2017"

        original = "1154:Syringe"


    condition:

        androguard.app_name("SmsManager") and 


        androguard.functionality.crypto.code(/invoke\-virtual\ v1\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\)\[B/) and 

        androguard.functionality.crypto.code(/invoke\-virtual\ v1\,\ v2\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\[B\)\[B/) and 

        androguard.functionality.crypto.method(/a/) and 

        androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 

        androguard.functionality.imei.method(/e/) and 

        androguard.functionality.installed_app.code(/invoke\-virtual\ v0\,\ v2\,\ Landroid\/content\/pm\/PackageManager\;\-\>getInstalledApplications\(I\)Ljava\/util\/List\;/) and 

        androguard.functionality.installed_app.method(/i/) and 

        androguard.functionality.socket.class(/Lcom\/aqplay\/shell\/i\;/) and 

        androguard.functionality.socket.code(/invoke\-virtual\ v0\,\ Ljava\/net\/URL\;\-\>openConnection\(\)Ljava\/net\/URLConnection\;/) and 

        androguard.functionality.socket.code(/invoke\-virtual\ v4\,\ Ljava\/net\/URL\;\-\>openConnection\(\)Ljava\/net\/URLConnection\;/) and 

        androguard.functionality.socket.method(/g/) and 


        androguard.number_of_activities == 2 and 


        androguard.number_of_filters == 10 and 


        androguard.number_of_receivers == 2 and 


        androguard.number_of_services == 3 and 


        androguard.package_name("com.sms.sys.manager") and 


        androguard.url("http://s.adslinkup.com/v2/ads/update/") and 

        androguard.url("http://t.adslinkup.com/v1/appevent/")

}