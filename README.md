Affected application: @Risk Palisade
Platform: Windows
Issue: Local Privilege Escalation via MSI installer (DLL hijacking race condition)
Discovered and reported by: Pawel Karwowski and Julian Horoszkiewicz (Eviden Red Team)

Details:
On systems with @RISK installed, it is possible for regular users to trigger the installer in "repair" mode, by issuing the following command:
msiexec.exe /fa PATH_TO_INSTALLER_FILE.msi

This triggers the msiexec service, which carries the repair process, running multiple actions and, between others, creates directories inside C:\Users\<username>\AppData\Local\Temp directory, which have their filenames dynamically generated, in following template: "{<36 characters with dashes inbetween>}", for example, {8A5C7026-A74E-447A-A762-3F021B26B525}. 

The process then uses the generated directories and writes various DLL files into them, which then are run as NT AUTHORITY/SYSTEM, for example, our file of interest, FnpCommsSoap.dll.

Since the C:\Users\pk\AppData\Local\ directory is owned by the regular user, the C:\Users\pk\AppData\Local\Temp\{*} directories inherit the permissions, making it possible for the regular user to interfere with the contents of the directory, for example by overwriting the dynamically generated DLL files.
This creates a race condition. If the regular user manages to locate the DLL file, they can attempt to overwrite them with their own file. If they manage to perform the replacement in the correct (very narrow) time window - right after the original file has been written by the installer and the file descriptor has been closed, but before the installer calls LoadLibrary() on it, they can get their own DLL file executed as NT AUTHORITY/SYSTEM, creating a Local Privilege Escalation.

Exploitation is done with the use of a C++ executable that runs the .MSI file, checks for the presence and creation of legit installer directories and DLL files of interest, and repeatedly copies both of my Proof of Concept DLLs into the Appdata\Local\Temp\<dynamically generated name> directory, effectively overwriting the legit DLL file. After being loaded, the PoC DLL file creates a poc.txt file in C:\Users\Public, together with the command line that called it, and whoami output. 

PLEASE NOTE:
this advisory contains several files, namely:
-the visual studio solution, with the source code of the exploit, and other project files (the naming convention is as follows: filename-<original extension>.txt; to use the files, rename them back to their original ext)
-the rogue DLL source code, named proxy.txt - for the proxy DLL file to work, it needs the original DLL in the same directory named as such: bak-FnpCommsSoap.dll - otherwise, the DLL and exploitation will fail
-additional screenshots taken while exploiting the vulnerability

Also, for the exploit to work, it needs to have both the DLL files in it's current working directory - proxy DLL (FnpCommsSoap.dll) and original DLL (bak-FnpCommsSoap.dll).
The rogue DLL file needs to be compiled as I-386/x32 architecture, as per the cl.exe command line provided in the beginning of its source file in a single line comment, the original DLL file is attached as solution/dllsource/bak-FnpCommsSoap-dll.txt to this advisory.

MSI file SHA256 sum:
AF182F42C9C80FDFCD304CA6B3AB68562B1FD6446D16BEB799A9EFE110858892

Original DLL file SHA256 sum:
E28A56F5C1BF3571B85ED85768F839BCDC9A84F3B9848EB5FCA71196E4B878A8
