rule Apkprotect
{
	meta:
		description = "Apkprotect"
		
    strings:
		$apkprotect_1 = ".apk@"
    	$apkprotect_2 = "libAPKProtect"
		$apkprotect_3 = "APKMainAPP"

	condition:
         ($apkprotect_1 and $apkprotect_2) or $apkprotect_3
}