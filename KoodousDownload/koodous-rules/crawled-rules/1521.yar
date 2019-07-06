
import "androguard"

import "file"

import "cuckoo"



rule SuspiciousAdds

{

    meta:

        description = "This rule looks for suspicios activity"


    condition:

        androguard.activity(/com.startapp.android.publish.OverlayActivity/i) or androguard.activity(/com.greystripe.sdk.GSFullscreenActivity/i)


}