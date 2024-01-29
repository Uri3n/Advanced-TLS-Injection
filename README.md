# Advanced-TLS-Injection
### A direct improvement to remote TLS Injection. Proof of concept

This is a PoC technique I created that has a similar objective to the one found by mrd0x, the founder of Maldev Academy.
The difference lies in the fact that this version can be performed on essentially *ANY* remote process you'd like,
making it significantly more powerful.

The original implementation relies on TLS callbacks being present within the executable image of the process you're targeting, 
as the TLS directory itself will not exist if TLS callbacks are not registered by the program. Additionally, it relies on creating a 
child process to host the payload, which it uses to execute the malicious callback.
