rule Ijiami
{
	meta:
		description = "Ijiami"
		
    strings:
		$1jiami_1 = "assets/ijiami.dat"
		$1jiami_2 = "ijiami.ajm"
		$1jiami_3 = "assets/ijm_lib/"
		$1jiami_4 = "libexecmain.so"
		$1jiami_5 = "libexec.so"
		$1jiami_6 = "rmeabi/libexecmain.so"
		$1jiami_7 = "neo.proxy.DistributeReceiver"

	condition:
        any of them 
}