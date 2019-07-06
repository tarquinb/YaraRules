
import "androguard"

import "cuckoo"



rule YaYaCryptocurrencyScams0: rule0 {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"

        date = "01 Mar 2018"


    condition:

        androguard.filter("com.google.android.c2dm.intent.RECEIVE") and 


        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/Context\;\-\>unregisterReceiver\(Landroid\/content\/BroadcastReceiver\;\)V/) and 

        androguard.functionality.socket.class(/Landroid\/support\/v4\/app\/NotificationManagerCompat\$SideChannelManager\;/) and 

        androguard.functionality.socket.method(/processListenerQueue/) and 


        androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 

        androguard.permission("android.permission.INTERNET") and 

        androguard.permission("android.permission.WAKE_LOCK") and 

        androguard.permission("com.google.android.c2dm.permission.RECEIVE")

}

import "androguard"

import "cuckoo"



rule YaYaCryptocurrencyScams1: rule1 {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"

        date = "01 Mar 2018"


    condition:

        androguard.app_name("Poloniex") and 


        androguard.displayed_version("1.0.0") and 


        androguard.functionality.dynamic_broadcast.class(/Lorg\/apache\/cordova\/CoreAndroid\;/) and 

        androguard.functionality.dynamic_broadcast.class(/Lorg\/apache\/cordova\/engine\/SystemWebViewEngine\;/) and 

        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/Context\;\-\>unregisterReceiver\(Landroid\/content\/BroadcastReceiver\;\)V/) and 

        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v1\,\ v2\,\ v0\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 

        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v10\,\ v11\,\ v6\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 

        androguard.functionality.dynamic_broadcast.method(/initTelephonyReceiver/) and 

        androguard.functionality.dynamic_broadcast.method(/initWebViewSettings/) and 

        androguard.functionality.dynamic_broadcast.method(/onDestroy/) and 

        androguard.functionality.run_binary.class(/Lorg\/apache\/cordova\/CordovaBridge\;/) and 

        androguard.functionality.run_binary.code(/const\-string\ v1\,\ \'Bridge\ access\ attempt\ with\ wrong\ secret\ token\,\ possibly\ from\ malicious\ code\.\ Disabling\ exec\(\)\ bridge\!\'/) and 

        androguard.functionality.run_binary.code(/const\-string\ v2\,\ \'exec\(\)\'/) and 

        androguard.functionality.run_binary.code(/invoke\-virtual\ v2\,\ v7\,\ v8\,\ v9\,\ v10\,\ Lorg\/apache\/cordova\/PluginManager\;\-\>exec\(Ljava\/lang\/String\;\ Ljava\/lang\/String\;\ Ljava\/lang\/String\;\ Ljava\/lang\/String\;\)V/) and 

        androguard.functionality.run_binary.method(/jsExec/) and 

        androguard.functionality.run_binary.method(/verifySecret/) and 

        androguard.functionality.sms.class(/Lorg\/apache\/cordova\/inappbrowser\/InAppBrowser\$InAppBrowserClient\;/) and 

        androguard.functionality.sms.code(/const\-string\ v7\,\ \'sms_body\'/) and 

        androguard.functionality.sms.method(/shouldOverrideUrlLoading/) and 

        androguard.functionality.socket.class(/Lorg\/apache\/cordova\/CordovaResourceApi\;/) and 

        androguard.functionality.socket.code(/invoke\-virtual\ v0\,\ Ljava\/net\/URL\;\-\>openConnection\(\)Ljava\/net\/URLConnection\;/) and 

        androguard.functionality.socket.code(/invoke\-virtual\ v2\,\ Ljava\/net\/URL\;\-\>openConnection\(\)Ljava\/net\/URLConnection\;/) and 

        androguard.functionality.socket.method(/createHttpConnection/) and 

        androguard.functionality.socket.method(/getMimeType/) and 

        androguard.functionality.socket.method(/openForRead/) and 

        androguard.functionality.ssl.class(/Lorg\/apache\/cordova\/CordovaResourceApi\;/) and 

        androguard.functionality.ssl.class(/Lorg\/apache\/cordova\/PluginManager\;/) and 

        androguard.functionality.ssl.class(/Lorg\/apache\/cordova\/Whitelist\;/) and 

        androguard.functionality.ssl.code(/const\-string\ v1\,\ \'https\'/) and 

        androguard.functionality.ssl.code(/const\-string\ v5\,\ \'https\:\/\/ssl\.gstatic\.com\/accessibility\/javascript\/android\/\'/) and 

        androguard.functionality.ssl.code(/const\-string\ v9\,\ \'https\'/) and 

        androguard.functionality.ssl.method(/addWhiteListEntry/) and 

        androguard.functionality.ssl.method(/getUriType/) and 

        androguard.functionality.ssl.method(/shouldAllowRequest/) and 


        androguard.number_of_activities == 1 and 


        androguard.number_of_filters == 1 and 


        androguard.number_of_permissions == 1 and 


        androguard.permission("android.permission.INTERNET")

}

import "androguard"

import "cuckoo"



rule YaYaCryptocurrencyScams2: rule2 {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"

        date = "01 Mar 2018"


    condition:

        androguard.certificate.sha1("FF0947D1B6240275301E77B00D78D2AC2173D2F3") and 


        androguard.functionality.dynamic_broadcast.class(/Landroid\/support\/v4\/media\/TransportMediatorJellybeanMR2\;/) and 

        androguard.functionality.dynamic_broadcast.class(/Landroid\/support\/v7\/app\/AppCompatDelegateImplV14\$AutoNightModeManager\;/) and 

        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/Context\;\-\>unregisterReceiver\(Landroid\/content\/BroadcastReceiver\;\)V/) and 

        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ v2\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 

        androguard.functionality.dynamic_broadcast.method(/cleanup/) and 

        androguard.functionality.dynamic_broadcast.method(/windowAttached/) and 

        androguard.functionality.dynamic_broadcast.method(/windowDetached/) and 

        androguard.functionality.imei.class(/Landroid\/support\/v7\/app\/AppCompatDelegateImplV9\;/) and 

        androguard.functionality.imei.class(/Landroid\/support\/v7\/app\/ToolbarActionBar\;/) and 

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

        androguard.functionality.socket.method(/sendRequest/) and 

        androguard.functionality.ssl.class(/Landroid\/support\/v4\/text\/util\/LinkifyCompat\;/) and 

        androguard.functionality.ssl.class(/Landroid\/support\/v4\/util\/PatternsCompat\;/) and 

        androguard.functionality.ssl.code(/const\-string\ v1\,\ \"\(\(\(\?\:\(\?i\:http\|https\|rtsp\)\:\/\/\(\?\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,64\}\(\?\:\\\\\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,25\}\)\?\\\\\@\)\?\)\?\(\?\:\"/) and 

        androguard.functionality.ssl.code(/const\-string\ v1\,\ \"\(\(\?\:\\\\b\|\$\|\^\)\(\?\:\(\?\:\(\?i\:http\|https\|rtsp\)\:\/\/\(\?\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,64\}\(\?\:\\\\\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,25\}\)\?\\\\\@\)\?\)\(\?\:\"/) and 

        androguard.functionality.ssl.code(/const\-string\ v1\,\ \'https\:\/\/\'/) and 

        androguard.functionality.ssl.method(/\<clinit\>/) and 

        androguard.functionality.ssl.method(/addLinks/) and 


        androguard.number_of_activities == 6 and 


        androguard.number_of_filters == 1

}

import "androguard"

import "cuckoo"



rule YaYaCryptocurrencyScams3: rule3 {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"

        date = "01 Mar 2018"


    condition:

        androguard.activity("com.myportablesoftware.minermonero.DebugActivity") and 

        androguard.activity("com.myportablesoftware.minermonero.MainActivity") and 


        androguard.app_name("Monero Miner (XMR)") and 


        androguard.certificate.sha1("DFC987EED1CABCB6C716FDE82A5F41A9CF477849") and 


        androguard.displayed_version("1.0") and 


        androguard.number_of_activities == 2 and 


        androguard.number_of_filters == 1 and 


        androguard.number_of_permissions == 1 and 


        androguard.package_name("com.myportablesoftware.minermonero") and 


        androguard.permission("android.permission.INTERNET")

}