import "androguard"
import "file"
import "cuckoo"


rule PornLock
{
	meta:
		description = "Rule to detect specific Porn related Lockscreen"
		sample = "f7c9a55d07069af95c18c8dd62b1c66568e3b79af551d95c7bf037a107e6526e"

	strings:
		$r = "res/xml/device_admin_data.xml"
		$b = "Update"
		$c = "XXX"
		$d = "Porn"
		$e = "Adult"

	condition:
	($r and androguard.service(/.Service\d{2}/) and $b and $c) or ($r and androguard.service(/.Service\d{2}/) and $b and $d) or ($r and androguard.service(/.Service\d{2}/) and $b and $e)
}