import "androguard"
import "file"
import "cuckoo"


rule BankBot : banker
{
	meta:
		description = "bankbot samples"

	strings:

		$strings_a = "de.dkb.portalapp"
		$strings_b = "de.adesso.mobile.android.gadfints"
		$strings_c = "de.commerzbanking.mobil"
		$strings_d = "de.ing_diba.kontostand"
		$strings_e = "de.postbank.finanzassistent"
		$strings_f = "com.isis_papyrus.raiffeisen_pay_eyewdg"

	

	condition:
		2 of ($strings_*)
}