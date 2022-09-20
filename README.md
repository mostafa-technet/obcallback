Anti Signed Exe Degrade.
The Driver prevents the unsigned exe files create processes that are signed. It is part of anti ransomeware system to prevent cheat the system by calling other processes that can modify files..


ObCallback Callback Registration Driver
=======================================

The ObCallback sample driver demonstrates the use of registered callbacks for process protection. The driver registers control callbacks which are called at process creation.


Design and Operation
--------------------

The sample exercises both the [**PsSetCreateProcessNotifyRoutineEx**](http://msdn.microsoft.com/en-us/library/windows/hardware/ff559951) and the [**ObRegisterCallbacks**](http://msdn.microsoft.com/en-us/library/windows/hardware/ff558692) routines. The first example uses the **ObRegisterCallbacks** routine and a callback to restrict requested access rights during a open process action. The second example uses the **PsSetCreateProcessNotifyRoutineEx** routine to reject a process creation by examining the command line.


