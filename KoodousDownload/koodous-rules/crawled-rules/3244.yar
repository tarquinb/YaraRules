
import "androguard"



 rule YaYaHummingBad2  {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (!) v0.3_summer17"

        date = "13 Jul 2017"

        original = "1187:HummingBad2"


    condition:

        androguard.filter("android.intent.action.MAIN") and 

        androguard.filter("android.intent.action.PACKAGE_ADDED") and 

        androguard.filter("android.intent.action.PACKAGE_CHANGED") and 

        androguard.filter("android.intent.action.PACKAGE_DATA_CLEARED") and 

        androguard.filter("android.intent.action.PACKAGE_REMOVED") and 

        androguard.filter("android.intent.action.PACKAGE_REPLACED") and 

        androguard.filter("android.intent.action.PACKAGE_RESTARTED") and 

        androguard.filter("android.intent.action.USER_PRESENT") and 

        androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and 


        androguard.functionality.dynamic_broadcast.class(/Lcom\/tencent\/bugly\/crashreport\/common\/strategy\/BuglyBroadcastRecevier\;/) and 

        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/Context\;\-\>unregisterReceiver\(Landroid\/content\/BroadcastReceiver\;\)V/) and 

        androguard.functionality.dynamic_broadcast.method(/finalize/) and 

        androguard.functionality.imei.class(/Lcom\/tencent\/bugly\/proguard\/a\;/) and 

        androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 

        androguard.functionality.imei.method(/a/) and 

        androguard.functionality.imsi.class(/Lcom\/tencent\/bugly\/proguard\/a\;/) and 

        androguard.functionality.imsi.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getSubscriberId\(\)Ljava\/lang\/String\;/) and 

        androguard.functionality.imsi.method(/b/) and 

        androguard.functionality.run_binary.code(/invoke\-static\ Ljava\/lang\/Runtime\;\-\>getRuntime\(\)Ljava\/lang\/Runtime\;/) and 

        androguard.functionality.socket.code(/invoke\-virtual\ v0\,\ Ljava\/net\/URL\;\-\>openConnection\(\)Ljava\/net\/URLConnection\;/) and 

        androguard.functionality.socket.method(/run/) and 

        androguard.functionality.ssl.class(/Lu\/aly\/cd\;/) and 

        androguard.functionality.ssl.code(/const\-string\ v2\,\ \'https\:\/\/\'/) and 

        androguard.functionality.ssl.method(/e/) and 


        androguard.number_of_permissions == 18 and 


        androguard.permission("android.permission.ACCESS_COARSE_LOCATION") and 

        androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 

        androguard.permission("android.permission.ACCESS_WIFI_STATE") and 

        androguard.permission("android.permission.BIND_ACCESSIBILITY_SERVICE") and 

        androguard.permission("android.permission.CHANGE_NETWORK_STATE") and 

        androguard.permission("android.permission.CHANGE_WIFI_STATE") and 

        androguard.permission("android.permission.DISABLE_KEYGUARD") and 

        androguard.permission("android.permission.GET_TASKS") and 

        androguard.permission("android.permission.INTERNET") and 

        androguard.permission("android.permission.MOUNT_UNMOUNT_FILESYSTEMS") and 

        androguard.permission("android.permission.READ_PHONE_STATE") and 

        androguard.permission("android.permission.SYSTEM_ALERT_WINDOW") and 

        androguard.permission("android.permission.VIBRATE") and 

        androguard.permission("android.permission.WAKE_LOCK") and 

        androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 

        androguard.permission("com.android.launcher.permission.INSTALL_SHORTCUT") and 

        androguard.permission("com.android.launcher.permission.READ_SETTINGS") and 

        androguard.permission("com.android.launcher.permission.UNINSTALL_SHORTCUT") and 


        androguard.url("http://218.70.17.178:3008/fkupdate.do") and 

        androguard.url("http://alog.umeng.co/app_logs") and 

        androguard.url("http://alog.umeng.com/app_logs") and 

        androguard.url("http://bugly.qq.com/whitebook") and 

        androguard.url("http://log.umsns.com/") and 

        androguard.url("http://log.umsns.com/share/api/") and 

        androguard.url("http://oc.umeng.co/check_config_update") and 

        androguard.url("http://oc.umeng.com/check_config_update") and 

        androguard.url("http://oc.umeng.com/v2/check_config_update") and 

        androguard.url("http://oc.umeng.com/v2/get_update_time") and 

        androguard.url("http://rqd.uu.qq.com/rqd/sync")

}