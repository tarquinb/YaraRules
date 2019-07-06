
import "androguard"

import "file"


rule koodous : official

{

    meta:

        description = "Ruleset to detect kwetza tool to inject malicious code in Android applications."

        url = "https://github.com/sensepost/kwetza"


    strings:

        $a = "maakDieStageVanTcp"wide ascii

        $b = "payloadStart"wide ascii

        $c = "leesEnLoopDieDing"wide ascii

    condition:

        all of them

}