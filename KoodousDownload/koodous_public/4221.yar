import "androguard"
import "cuckoo"


rule YaYaSMSFraud0: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "20 Feb 2018"

	condition:
		androguard.activity("com.alipay.sdk.app.H5PayActivity") and 

		androguard.filter("io.dcloud.ACTION_PICK") and 

		androguard.functionality.dynamic_broadcast.class(/Lcom\/alipay\/sdk\/app\/PayTask\$6\$2\;/) and 
		androguard.functionality.dynamic_broadcast.method(/onClick/) and 
		androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.imsi.class(/Lcom\/android\/dd\/data\/ChangeNetwork\;/) and 
		androguard.functionality.imsi.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getSubscriberId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.imsi.method(/c/) and 
		androguard.functionality.phone_number.method(/a/) and 
		androguard.functionality.sms.code(/invoke\-virtual\/range\ v0\ \.\.\.\ v5\,\ Landroid\/telephony\/SmsManager\;\-\>sendTextMessage\(Ljava\/lang\/String\;\ Ljava\/lang\/String\;\ Ljava\/lang\/String\;\ Landroid\/app\/PendingIntent\;\ Landroid\/app\/PendingIntent\;\)V/) and 
		androguard.functionality.ssl.method(/uploadCollectedData/) and 

		androguard.number_of_services == 1 and 

		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.RECORD_AUDIO") and 
		androguard.permission("android.permission.VIBRATE") and 
		androguard.permission("com.android.launcher.permission.INSTALL_SHORTCUT")
}

import "androguard"
import "cuckoo"


rule YaYaSMSFraud1: rule1 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "20 Feb 2018"

	condition:
		androguard.functionality.phone_number.method(/cooeeGetPhoneNumber/) and 

		androguard.permission("android.permission.GET_TASKS") and 

		androguard.receiver("com.fanwei.sdk.push.FanweiReceiver") and 
		androguard.receiver("com.yuelan.dreampay.service.StartReceiver") and 

		androguard.service("com.yuelan.codelib.download.DownLoadService") and 
		androguard.service("com.yuelan.dreampay.service.ShieldSmsService") and 

		(androguard.url("http://121.199.52.42:83/danji/") or 
		cuckoo.network.dns_lookup(/121\.199\.52\.42/)  or 
		cuckoo.network.http_request(/121\.199\.52\.42/)) and 

		(androguard.url("http://211.139.191.223:22222/trust") or 
		cuckoo.network.dns_lookup(/211\.139\.191\.223/)  or 
		cuckoo.network.http_request(/211\.139\.191\.223/)) and 

		(androguard.url("http://211.139.191.223:22222/trusted3") or 
		cuckoo.network.dns_lookup(/211\.139\.191\.223/)  or 
		cuckoo.network.http_request(/211\.139\.191\.223/)) and 

		(androguard.url("http://leyifu.astep.cn:9000/versionpatch") or 
		cuckoo.network.dns_lookup(/leyifu\.astep\.cn/)  or 
		cuckoo.network.http_request(/leyifu\.astep\.cn/)) and 

		(androguard.url("http://pay3.miliroom.com:13579/SMSpay/api") or 
		cuckoo.network.dns_lookup(/pay3\.miliroom\.com/)  or 
		cuckoo.network.http_request(/pay3\.miliroom\.com/)) and 

		(androguard.url("http://pu.miliroom.com:6680/ADSts") or 
		cuckoo.network.dns_lookup(/pu\.miliroom\.com/)  or 
		cuckoo.network.http_request(/pu\.miliroom\.com/))
}