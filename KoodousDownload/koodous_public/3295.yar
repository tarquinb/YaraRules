import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{

	strings:
		$a = "your files have been encrypted!"
		$b = "your Device has been locked"
		$c = "All information listed below successfully uploaded on the FBI Cyber Crime Depar"

	condition:
		$a or $b or $c or androguard.package_name("com.android.admin.huanmie") or androguard.package_name("com.android.admin.huanmie")
		
}