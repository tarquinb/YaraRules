rule packers : baidu
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:
		$baidu_1 = "libbaiduprotect.so"
		$baidu_2 = "baiduprotect.jar"
		$baidu_3= "libbaiduprotect_x86.so"

	condition:
		all of them
		
}