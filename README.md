# Hermes
## Windows Keylogging Malware

Keylogging malware that exfiltrates every key that the victim presses, 512 keys at a time. The keys 
are XOR encrypted with a 64-byte, randomly generated key, and then sent over to an external C2 server.
Basic functionality is all that has been implemented so far, this time without the CRT. 

Hermes isn't *very* stealthy, for now, so a fairly competent user could still catch wind of something
fishy going on with their machine. The traffic Hermes sends goes through port 80, so it looks like
rudimentary HTTP data. Hermes is also discoverable in the Task Manager, so the next step in its 
development is an implementation of process injection such that Anti-Viruses will not detect what 
it's doing. 

### TODO:
* ~~Log keystrokes~~
* ~~Translate keys from Virtual Key Codes~~
* ~~Exfiltrate keys over the network~~
* ~~Add basic encryption to key buffer during exfil~~
* ~~Add cleanup routine~~
* ~~Remove CRT (This was a first for me, but finally got it working with some guidance from Rez :) )~~
* Implement Process Injection for improved stealth
* Increase key buffer size

## Disclaimer:
Hermes and all related malware that I create is the work of my curiosity and is created in the spirit of
learning. As such, I highly discourage using this software to exploit unsuspecting users
for fun or for profit, and I will not take responsibility for the (ab)use of this or any future
malware technology that I create, should it be used for any malicious activity. Hacking isn't 
inherently malicious, neither is knowledge nor creativity. **If you are to use this code for 
any malicious activity of any kind, that falls squarely on you and you _alone_**. 