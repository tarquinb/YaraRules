import "androguard"

rule Android_RuMMS
{
	meta:
		author = "reverseShell - https://twitter.com/JReyCastro"
		date = "2016/04/02"
		description = "This rule try to detects Android.Banking.RuMMS"
		sample = "13569bc8343e2355048a4bccbe92a362dde3f534c89acff306c800003d1d10c6 "
		source = "https://www.fireeye.com/blog/threat-research/2016/04/rumms-android-malware.html"

	condition:
		all of ($string_*) and
		androguard.package_name("org.starsizew") or
		androguard.package_name("com.tvone.untoenynh") or
		androguard.package_name("org.zxformat") and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)
		
}