import "androguard"

rule android_dropper_sh
{
	meta:
		description = "Yara rule for detection of Android dropper.c samples"
		sample = "cad5d7125a28f7b1ea6ff6d358c05d25cdb2fd5c21e3f6e0973ea7c5a47206a3"
		source = "https://goo.gl/VBalPr"
		author = "https://twitter.com/5h1vang"
		
	strings:
		$str_1 = "s_s_dcqjwouifi"
		$str_2 = "${LIBS_DIR}"
		$str_3 = "${ODEX_DIR}"
		$str_4 = "DES/CBC/PKCS5Padding"

	condition:
		androguard.certificate.sha1("7D4A2A6087D6F935E9F80A8500C42DB912C270C6") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and 
		all of ($str_*)
				
}