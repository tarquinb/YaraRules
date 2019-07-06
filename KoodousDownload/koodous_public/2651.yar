import "androguard"
import "file"
import "cuckoo"


rule Target_Bank_Paypal : official
{
	strings:
		$string_target_bank_paypal = "com.paypal.android.p2pmobile"
	condition:

	($string_target_bank_paypal)
}