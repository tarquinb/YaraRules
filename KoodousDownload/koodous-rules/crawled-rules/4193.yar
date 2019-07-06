
import "androguard"

import "cuckoo"



rule YaYaRule: rule0 {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"

        date = "09 Feb 2018"


    condition:

        androguard.certificate.sha1("A94017A56275BBAC8C31166CCE314A49C029E959") or 

        (androguard.filter("android.intent.action.BOOT_COMPLETED") and 


        androguard.functionality.dynamic_broadcast.class(/Landroid\/support\/v7\/app\/AppCompatDelegateImplV14\$AutoNightModeManager\;/) and 

        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/Context\;\-\>unregisterReceiver\(Landroid\/content\/BroadcastReceiver\;\)V/) and 

        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ v2\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 

        androguard.functionality.dynamic_broadcast.method(/cleanup/) and 

        androguard.functionality.dynamic_broadcast.method(/setup/) and 

        androguard.functionality.imei.class(/Landroid\/support\/v7\/app\/AppCompatDelegateImplV9\;/) and 

        androguard.functionality.imei.class(/Landroid\/support\/v7\/app\/ToolbarActionBar\;/) and 

        androguard.functionality.imei.class(/Landroid\/support\/v7\/app\/WindowDecorActionBar\;/) and 

        androguard.functionality.imei.code(/invoke\-virtual\ v11\,\ Landroid\/view\/KeyEvent\;\-\>getDeviceId\(\)I/) and 

        androguard.functionality.imei.code(/invoke\-virtual\ v7\,\ Landroid\/view\/KeyEvent\;\-\>getDeviceId\(\)I/) and 

        androguard.functionality.imei.method(/onKeyShortcut/) and 

        androguard.functionality.imei.method(/preparePanel/) and 

        androguard.functionality.socket.class(/Landroid\/support\/v4\/app\/NotificationManagerCompat\$SideChannelManager\;/) and 

        androguard.functionality.socket.class(/Landroid\/support\/v4\/media\/MediaBrowserCompat\$ServiceBinderWrapper\;/) and 

        androguard.functionality.socket.class(/Landroid\/support\/v4\/os\/ResultReceiver\;/) and 

        androguard.functionality.socket.code(/invoke\-interface\ v0\,\ v3\,\ v4\,\ Landroid\/support\/v4\/os\/IResultReceiver\;\-\>send\(I\ Landroid\/os\/Bundle\;\)V/) and 

        androguard.functionality.socket.code(/invoke\-interface\ v1\,\ v2\,\ Landroid\/support\/v4\/app\/NotificationManagerCompat\$Task\;\-\>send\(Landroid\/support\/v4\/app\/INotificationSideChannel\;\)V/) and 

        androguard.functionality.socket.code(/invoke\-virtual\ v1\,\ v0\,\ Landroid\/os\/Messenger\;\-\>send\(Landroid\/os\/Message\;\)V/) and 

        androguard.functionality.socket.method(/processListenerQueue/) and 

        androguard.functionality.socket.method(/send/) and 

        androguard.functionality.socket.method(/sendRequest/)) or


        (androguard.url("http://lp.androidapk.world/?appid=") or 

        cuckoo.network.dns_lookup(/lp\.androidapk\.world/)  or 

        cuckoo.network.http_request(/lp\.androidapk\.world/))

}