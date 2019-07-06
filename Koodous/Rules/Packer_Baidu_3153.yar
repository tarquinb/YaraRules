rule Baidu
{
	meta:
		description = "Baidu"
		
    strings:
		$baidu_1 = "libbaiduprotect.so"
		$baidu_2 = "baiduprotect1.jar"
		$baidu_3 = "baiduprotect.jar"
		$baidu_4= "libbaiduprotect_x86.so"
		$baidu_5 = "com.baidu.protect.StubApplication"
		$baidu_6 = "com.baidu.protect.StubProvider"
		$baidu_7 = "com.baidu.protect.A"
		$baidu_8 = "libbaiduprotect"

	condition:
        any of them 
}