rule SMSReg
{
        meta:
                description = "This rule detects SMSReg apps"
                sample = "ed3c5d4a471ee4bf751af4b846645efdeafcdd5f85c1f3bdc58b84119b7d60e8"
				packagename = "com.sm.a36video1"

        strings:
                $a = "kFZFZUIF"
                $b = "btn_title_shop"
                $c = "more_about_version" wide
                $d = "$on}$fxfThjfnyj$hdembl;"
                $e = "ad_video_vip" wide

        condition:
                all of them

}