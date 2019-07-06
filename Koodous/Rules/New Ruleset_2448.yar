import "androguard"

rule sensual_woman: chinese
{
	condition:
		androguard.package_name(/com.phone.gzlok.live/)
		or androguard.package_name(/com.yongrun.app.sxmn/)
		or androguard.package_name(/com.wnm.zycs/)
		or androguard.package_name(/com.charile.chen/i)
		or androguard.package_name(/com.sp.meise/i)
		or androguard.package_name(/com.legame.wfxk.wjyg/)
}
rule SMSSend
{
	strings:
		$a = "bd092gcj"
		$b = "6165b74d-2839-4dcd-879c-5e0204547d71"
		$c = "SELECT b.geofence_id"
		$d = "_ZN4UtilD0Ev"

	condition:
		all of them
}

rule SMSSend2
{
	strings:
		$a = "SHA1-Digest: zjwp/bYwUC5kfWetYlFwr/EuHac="
		$b = "style_16_4B4B4B"
		$c = "style_15_000000_BOLD"

	condition:
		all of them
}