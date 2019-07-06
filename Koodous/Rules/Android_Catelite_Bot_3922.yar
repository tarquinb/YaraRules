import "androguard"
import "droidbox"


rule catelites
{

               strings:
                              $db1 = "Successfully updated \"%1$s\""
                              $db2 = "Added %1$s to %2$s balance."
                              $db3 = "Touch to sign in to your account."
                              $db4 = "You will be automatically charged %1$s"

               condition:
                              all of them
                              or
                              (
                                            droidbox.written.filename(/V3a3i1iqN.xml/) and
                                            droidbox.written.data(/http/)
                              )
                              
}