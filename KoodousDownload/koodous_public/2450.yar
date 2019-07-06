import "androguard"


rule RootedCheck 
{
	meta:
		description = "This rule detects applications checking for/or requiring root access."

	strings:
		$a = "bin/which su"
		$b = "/sbin/su"
		$c = "system/bin/su"
		$d = "bin/which su"
		$e = "Superuser.apk"
		$f = "/system/xbin/su"
		$g = "/data/local/xbin/su"
		$h = "/data/local/bin/su"
		$i = "/system/sd/xbin/su"
		$j = "/system/bin/failsafe/su"
		$k = "/data/local/su"
		$l = "/system/xbin/which"
		$m = "which su"

		
	condition:
		$a or
		$b or
		$c or
		$d or
		$e or
		$f or
		$g or
		$h or
		$i or
		$j or
		$k or
		$l or $m

}