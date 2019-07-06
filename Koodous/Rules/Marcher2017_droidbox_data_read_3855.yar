import "androguard"
import "file"
import "cuckoo"
import "droidbox"


rule marcher_2017
{
	meta:
		description = "This rule detects the marcher trojan, based on read data"
		sampleSHA256 = "a6d9ccf67f2c09ea5c5bceb5f9921861d615462bf56a72c26f180d5ed5297914"

	//strings:
		//$magic_string = "/**[a-aA-Z0-9].{1,4}**/"
		//$activity_name = "/p0[0-9]{1,3}[a-z]/"
	condition:
		//$magic_string and
		androguard.min_sdk >= 14 and
			droidbox.read.data("504b05060000000030013001cc730000ed620a000000504b010214001400000808000000000081394c1e5d0c00008c390000130004000000000000000000000000000000416e64726f69644d616e69666573742e786d6cfeca0000504b0102180014000000080000000000d44e28a7160400005205000011000000000000000000000000008e0c00004d4554412d494e462f434552542e525341504b010218001400000008000000000010533c5f99210000f37b00001000000000000000000000000000d31000004d4554412d494e462f434552542e5346504b0102180014000000080000000000ae0ca59d7b210000c87b000014000000000000000000000000009a3200004d4554412d494e462f4d414e49464553542e4d46504b010218001400000008000000000005277fc1f2ce0300dce909000b0000000000000000000000000047540000636c61737365732e646578504b01021400140000080800000000004356e6d72f000000680000001800000000000000000000000000622304007265732f616e696d2f6162635f666164655f696e2e786d6c504b01021400140000080800000000004356e6d72f000000680000001900000000000000000000000000c72304007265732f616e696d2f6162635f666164655f6f75742e786d6c504b010214001400000808000000000069d6fbb8810100005c03000029000000") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.WRITE_SMS/) and
		androguard.permission(/android.permission.READ_CONTACTS/)
}