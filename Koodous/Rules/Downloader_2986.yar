import "androguard"

rule Downloader {
	condition:
		androguard.package_name("com.mopub") and
		androguard.filter("android.intent.action.ACTION_SHUTDOWN") and
		androguard.filter("android.net.wifi.supplicant.CONNECTION_CHANGE") and
		androguard.filter("android.intent.action.QUICKBOOT_POWEROFF") and
		androguard.filter("android.net.wifi.STATE_CHANGE") and
		androguard.filter("android.intent.action.BOOT_COMPLETED") and
		androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and
		androguard.filter("android.net.wifi.WIFI_STATE_CHANGED") and
		androguard.filter("android.intent.action.REBOOT")
}