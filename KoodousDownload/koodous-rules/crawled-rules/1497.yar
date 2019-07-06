
import "file" 



rule FaceAdware

{

    meta:

        description = "Adware pretending to be a Whatsapp or Facebook hack."

        sample = "https://analyst.koodous.com/apks?search=3d2f4b7abbf8b80982b0100835427ac8%20%20748de691ed7a407b169ffe102ed6f71e%20%20098c5f83f732e9b22a3e19a6523a5f8d%20%20c81c519a151f2611cc30ee4756c94f30"


    strings:

        $pub_id = "ca-app-pub-5886589216790682/8233759652"

        $pub_id2 = "ca-app-pub-5886589216790682/9710492858"


    condition:

        $pub_id or $pub_id2 


}