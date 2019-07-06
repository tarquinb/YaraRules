import "androguard"
import "file"
import "cuckoo"


rule ijiami : packer
{
  meta:
    description = "Ijiami"

  strings:
    $old_dat = "assets/ijiami.dat"
    $new_ajm = "ijiami.ajm"
    $ijm_lib = "assets/ijm_lib/"

  condition:
    ($old_dat or $new_ajm or $ijm_lib)
}