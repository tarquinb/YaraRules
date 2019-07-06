
import "androguard"

import "cuckoo"



rule fakeinstaller

{

    meta:

        sample = "e39632cd9df93effd50a8551952a627c251bbf4307a59a69ba9076842869c63a"


    condition:

        androguard.permission(/com.android.launcher.permission.INSTALL_SHORTCUT/)

        and androguard.permission(/android.permission.SEND_SMS/)

        and androguard.certificate.sha1("E030A31BE312FF938AAF3F314934B1E92AF25D60")

        and androguard.certificate.issuer(/hghjg/)

}