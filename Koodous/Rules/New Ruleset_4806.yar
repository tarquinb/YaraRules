import "androguard"
import "file"
import "cuckoo"
import "droidbox"


rule Banker : BankBot
{
	meta:
		description = "for banker"
		sample = "e725a7efd60f8d44889bce2c6115b247b665af215bc29330fddc8d07a1730ad2"

	condition:
		droidbox.read.filename("/image/files") and
		androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/)
		
}