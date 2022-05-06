# Hermes
## Windows Keylogging Malware

This is the official first version of Hermes. There are a lot of things that could still be done, 
but for the goal I had in mind for this project, I am satisfied. Any further adjustments and features could be built
upon this version. I believe it serves as a great skeleton for a keylogger or any such spyware.

## Features
- **Logging Keystrokes** : Hermes, as it is in this repository, is a relatively simple keylogger. As stated before, it records around 512 keys
                           before exfiltrating to the C2.
                           
- **Stealth**            : It uses legitimate-looking ports for communication with the C2, on top of _process injection_. Hermes will also delete
                           itself off disk once it is run. This makes it particlularly difficult to notice for an unsuspecting user or one that is
                           not particularly observant during the time in which Hermes is running.
 
- **Process Injection**  : Hermes now will not run if the process who called it is itself. That is, it will search for a separate process running 
                           on the machine into which it will inject itself. The technique I used here is refered to as PE Hollowing, which I discovered 
                           and learned about from one of the articles at ired.team. 
                  
- **Memory Resident**    : Once Hermes is executed, without need for admin priveleges, it will delete itself off the hard drive of the host machine
                           and continue its execution without ever writing anything to the hard drive, and it makes an effort to clean out its buffers
                           as often as possible.

## Shortfalls 
- _Volatile_ :
Due to its memory-resident nature, and its lack of reboot-persistance facilities, rebooting the host machine would effectively kill all active 
instances of Hermes.

- _Stuttering_ :
Depending on how many processes are specified to be infected, there may be a noticible stutter when typing, depending on the specs of the infected 
machine. While running on my VM --to which I allocated 4GB of memory-- there was a major stutter when Hermes was launched, but not much therafter. 
I also noticed that when I typed something really quickly my VM began to lag ever so slightly.

- _Detectable by AV_ :
Hermes' behaviour is more than likely to trigger some alarms, or, at the very least, be put under suspicion immediately by AVs. Hooking events isn't 
in and of itself enough of a flag, but Hermes, as it is now, blatantly hooks one kind of event: The keyboard. On top of that, it has a lot of the
telltale features of malware; checks for the presence of a debugger, communication with a remote machine, creating and executing remote threads, etc.
A lot of suspicion could be averted depending on how the executable is compiled, packed, and, optionally --if possible--, signed. 

## Disclaimer:
Hermes and all related malware that I create is the work of my curiosity and is created in the spirit of
learning. As such, I highly discourage using this software to exploit unsuspecting users
for fun or for profit, and I will not take responsibility for the (ab)use of this or any future
malware technology that I create, should it be used for any malicious activity. Hacking isn't 
inherently malicious, neither is knowledge nor creativity. **If you are to use this code for 
any malicious activity of any kind, that falls squarely on you and you _alone_**. 
