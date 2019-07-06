
import "androguard"



rule YaYaSmsSenderOpt1 {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (!) v0.3_summer17"

        date = "24 Aug 2017"

        original = "874:SmsSender"


    condition:

        androguard.displayed_version("1.0") and 


        androguard.functionality.dynamic_broadcast.class(/Lcom\/software\/application\/Actor\;/) and 

        androguard.functionality.dynamic_broadcast.class(/Lcom\/software\/application\/Main\$4\;/) and 

        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ v2\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 

        androguard.functionality.dynamic_broadcast.method(/acquire/) and 

        androguard.functionality.dynamic_broadcast.method(/onReceive/) and 

        androguard.functionality.mcc.class(/Lcom\/software\/application\/Main\;/) and 

        androguard.functionality.mcc.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getNetworkOperator\(\)Ljava\/lang\/String\;/) and 

        androguard.functionality.mcc.method(/onCreate/) and 

        androguard.functionality.socket.class(/Lcom\/software\/application\/Actor\;/) and 

        androguard.functionality.socket.method(/report/) and 


        androguard.main_activity("com.software.application.Main") and 


        androguard.number_of_activities == 3 and 


        androguard.package_name("com.software.application")

}


rule YaYaSmsSenderOpt2 {

    meta:

        author = "YaYaGen -- Yet Another Yara Rule Generator (!) v0.3_summer17"

        date = "24 Aug 2017"

        original = "874:SmsSender"


    condition:

        androguard.displayed_version("1.0") and 


        androguard.functionality.dynamic_broadcast.class(/Lcom\/software\/application\/Actor\;/) and 

        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ v2\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 

        androguard.functionality.dynamic_broadcast.method(/acquire/) and 

        androguard.functionality.dynamic_broadcast.method(/onReceive/) and 

        androguard.functionality.mcc.class(/Lcom\/software\/application\/Main\;/) and 

        androguard.functionality.mcc.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getNetworkOperator\(\)Ljava\/lang\/String\;/) and 

        androguard.functionality.mcc.method(/onCreate/) and 

        androguard.functionality.socket.class(/Lcom\/software\/application\/Actor\;/) and 

        androguard.functionality.socket.method(/activate/) and 

        androguard.functionality.socket.method(/report/) and 


        androguard.main_activity("com.software.application.Main") and 


        androguard.number_of_activities == 3 and 


        androguard.package_name("com.software.application")

}