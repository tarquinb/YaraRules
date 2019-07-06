
import "androguard"


rule Locker_K

{

    meta:

        description = "This rulset detects the Android Screen Locker"

        date = "06-July-2016"

        sample = "e8c9bc0f37395572a6ad43a4f1e11f8eeb86b6f471f443714f6fb1bcb465e685"


    strings:

        $a = "<br>Do not turn off or reboot your phone during update"


    condition:

        androguard.filter(/DEVICE_ADMIN_ENABLED/) and

        androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and $a


}