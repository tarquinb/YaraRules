rule Packer_Bangcle
{
	meta:
		description = "Bangcle (SecApk)"
		
    strings:
		$bangcle_1 = "libsecmain.so"
		$bangcle_2 = "libsecexe.so"
		$bangcle_3 = "bangcleplugin"	
		$bangcle_4 = "libsecexe.x86"
		$bangcle_5 = "libsecmain.x86"
		$bangcle_6 = "SecApk"
		$bangcle_7 = "bangcle_classes"	
		$bangcle_8 = "assets/bangcleplugin"
		$bangcle_9 = "neo.proxy.DistributeReceiver"

		$bangcle_10 = "libapkprotect2.so"
		$bangcle_11 = "assets/bangcleplugin/container.dex"
		$bangcle_12 = "bangcleclasses.jar"
		$bangcle_13 = "bangcle_classes.jar"
		
	condition:
        any of them 
}