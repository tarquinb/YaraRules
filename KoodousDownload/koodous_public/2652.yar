import "androguard"
import "file"
import "cuckoo"


rule Target_Bank_DB : official
{
	strings:
		$string_target_bank_db = "com.db.mm.deutschebank"
	condition:

	($string_target_bank_db)
}