import "androguard"

rule SLockerQQ
{
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/new-wannacry-mimicking-slocker-abuses-qq-services/"
		
	condition:
		androguard.package_name("com.android.admin.hongyan") or
		androguard.package_name("com.android.admin.huanmie") or
		androguard.app_name("TyProxy")
}