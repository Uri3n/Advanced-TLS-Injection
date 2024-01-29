# Advanced-TLS-Injection
### A direct improvement to remote TLS Injection. Proof of concept

This is a PoC technique I created that has a similar objective to the one found by mrd0x, the founder of Maldev Academy.
The difference lies in the fact that this version can be performed on essentially *ANY* remote process you'd like,
making it significantly more powerful.

The original implementation relies on TLS callbacks being present within the executable image of the process you're targeting, 
as the TLS directory itself will not exist if TLS callbacks are not registered by the program. Additionally, it relies on creating a 
child process to host the payload, which it uses to execute the malicious callback.

This PoC does two things differently. Firstly, it targets a core Windows subsystem DLL, KernelBase.dll. This DLL is loaded into virtually every
process in Windows, making it extremely reliable. When threads "attach" themselves to a DLL, which is essentially just when any thread is created once
the DLL is mapped, that thread will have to execute all TLS callbacks associated with the module.
You may be thinking to yourself: "Okay, well how do we trigger the payload then? Do we have to wait around for a new thread to be created?" No.
We can use NtSetInformationWorkerFactory to raise the minimum number of threads within the process' thread pool, essentially forcing the creation of a new 
worker thread to execute our malicious callback.

### Important
This is a proof of concept. Some things would need improvement on your end if you plan on using this in your code.
Namely, the TLS callback address is not reverted back to a null pointer here, because the calc payload used for testing
crashes the process anyway. In a real scenario, make sure you revert the TLS callback pointer within the TLS directory. This will 
prevent your payload from accidentally being ran more than once.
