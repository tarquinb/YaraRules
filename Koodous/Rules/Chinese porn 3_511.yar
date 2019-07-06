import "androguard"
rule chinese_porn : SMSSend
{

	condition:
		androguard.package_name("com.tzi.shy") or
		androguard.package_name("com.shenqi.video.nfkw.neim") or
		androguard.package_name("com.tos.plabe")
}