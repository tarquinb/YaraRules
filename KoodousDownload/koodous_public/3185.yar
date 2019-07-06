import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "FinFisher"

	condition:
		androguard.app_name("cloud service") and
		androguard.permission(/android.permission.RECORD_AUDIO/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.CALL_PHONE/) and
		androguard.permission(/android.permission/) and
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/)
}