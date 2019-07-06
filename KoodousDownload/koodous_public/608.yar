import "androguard"


rule AirPush : AirPush
{
	meta:
		description = "This rule detects AirPush"

	strings:
		$type_a_1 = "ZeIdg9Q9b"
		$type_a_2 = "lib/armeabi/libcrypt.so"
		
		$type_b_1 = "res/menu/install_games.xml"
		$type_b_2 = "resources.zip"
		$type_b_3 = "XCIFLNLKNFVVKHFFW"
		
		/*$type_c_1 = "CHUma aplica"
		$type_c_1 = "Theme.IAPTheme"*/

	condition:

		all of ($type_a_*) and androguard.activity(/com.intrinsic.*/) or
		all of ($type_b_*) and androguard.activity(/com.yzurhfxi.*/)
		//all of ($type_c_*) and androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/)
		
		
		
}
/* 

TYPE A samples
579549ac5265e870a2f11e1803416c205b5def1684617015bbd2eec3eb32561d
f5e7ba670f9fef3aa6aaf9069ce51d2db65f6d3c5a581510b806cb2584370eaf
90059107a1cf9c2bab614590d247e7d149dca07db74baef726e78f2f34f1bef5

TYPE B samples
579549ac5265e870a2f11e1803416c205b5def1684617015bbd2eec3eb32561d
f5e7ba670f9fef3aa6aaf9069ce51d2db65f6d3c5a581510b806cb2584370eaf
90059107a1cf9c2bab614590d247e7d149dca07db74baef726e78f2f34f1bef5

TYPE C samples
5f471f4b586be6648d0237c6873297357005edb2d302aea9b33e1b12c7a9f7c0
6829ddbc8f666d796bb0f3383d61f76807af37880142f24ac96e2f0a4bc04b58
ed1d1a0521713c71dedf1968d09b8b15dddcc531ccc158a9e881bea4e0e5fee3

*/