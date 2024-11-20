# Advanced-TLS-Injection-PoC
### A Threadless Injection Technique That Abuses TLS callbacks.

I did a write-up on this. Check it out here: https://masq.foo/html/posts/tlscallbacks.html

This is a PoC technique I created that has a similar objective to the technique found by mrd0x, the founder of Maldev Academy.
The difference lies in the fact that this version can be performed on essentially *ANY* remote process you'd like,
making it significantly more powerful. For more details on how it works, check the link above.

### Important
This is a proof of concept. Some things would need improvement on your end if you plan on using this in your code.
Namely, the TLS callback address is not reverted back to a null pointer here, because the calc payload used for testing
crashes the process anyway. In a real scenario, make sure you revert the TLS callback pointer within the TLS directory. This will 
prevent your payload from accidentally being ran more than once.
