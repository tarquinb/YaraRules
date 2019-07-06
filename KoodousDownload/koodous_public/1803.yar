import "androguard"
import "file"
import "cuckoo"

rule r
{
    strings:
        $re1 = /scripts\/action_request.php$/

    condition:
        $re1
}