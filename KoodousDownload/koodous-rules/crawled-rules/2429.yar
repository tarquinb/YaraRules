
import "androguard"

import "file"

import "cuckoo"



rule OmniRAT : RAT

{

    meta:

        description = "OmniRAT"


    strings:

        $name = "com.android.engine"

        $s_1 = "DeviceAdmin"

        $s_2 = "SMSReceiver"


    condition:

        2 of ($s_*)

        and $name

        and androguard.permission(/android.permission.RECEIVE_SMS/)

        and androguard.permission(/android.permission.READ_CONTACTS/)

        and androguard.permission(/android.permission.SEND_SMS/)

        and androguard.permission(/android.permission.WRITE_SMS/)

        and androguard.permission(/android.permission.BLUETOOTH_ADMIN/)

        and androguard.permission(/android.permission.MANAGE_ACCOUNTS/)

        and androguard.filter(/android.app.action.DEVICE_ADMIN_ENABLED/)

        and androguard.filter(/android.provider.Telephony.SMS_RECEIVED/)

        and androguard.filter(/android.intent.action.BOOT_COMPLETED/)

}