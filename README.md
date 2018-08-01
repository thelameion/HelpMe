# HelpMe
Troubleshooting your Windows Server
_____________________________________________
Basic Troubleshooting Steps for RDP:
1. Check the error message and try to understand what that message means.
2. Try to ping the terminal services and check if it is pinging.
3. On Terminal server check if Term service is listening on port 3389 using command net stat  –anob.
4. Check if RDP is enabled (sysdm.cpl) and users have permissions.
5. Check if it is blocked by firewall, Disable firewall and check if RDP is working.
6. Check if 3389 port is taken by any 3rd party service/app. Check by using command net stat  –anob. Now disable 3rd party apps and check if rdp is working.
7. Make sure RDS is started and is on running state.
8. Try to change the security layer from negotiate to RDP security layer.
9. Change RDP port and check if it is working.
10. Recreate the listener using TSconfig.msc on the server
11. Try to telnet on port 3389 from client machine to terminal server and check if it connects.
12. Update RDP binaries on client and server. 

 Troubleshooting steps for Spooler Hang / Crash:
1. Run print and perf MSDT.
2. Do print hive cleaning.
3. Check event id in event viewer (1000 id for any app crash).
4. If event id for crash found check faulty module. Rename to .old only for 3rd party dll.
5. Take dump using procdump tool.

Troubleshooting Steps for Unable to Print:
1. Get all the Environment details and network connectivity details.
2. Run Print MSDT and Perf MSDT.
3. Check the error message.
4. Check the status of the spooler service (spoolsv.exe)
5. Check the event logs at the time of issue (system, application, print service log).
6. Change printer driver to generic text and try to print.
7. Do a print hive cleaning.
8. Update print related binaries on client and server (windows update).
9. Update print drivers.

Troubleshooting steps for Blank Desktop / unable to launch explorer.exe:
1. Try to run explorer.exe in task manager and check if we can see desktop.
2. If in task manager does not launch explorer.exe then try to run explorer.exe as an admin in task manager.
3. If explorer.exe launches as an admin then it can be permission issue. Compare permissions from working machine for explorer.exe and shell32.dll or use procmon tool.
4. Check the below registry. The value should be as below
	HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsNT\Currentversion\Win logon 
      Name: USERINIT
      Value:  C:\Windows\System32\Userinit.exe
      Name: SHELL
      Value: Explorer.exe
	
5.  Run Autoruns and remove all the 3rd party extensions from explorer.exe.
6. Run below command if still the issue is not resolved dism /online/cleanup-image/restore health
	sfc /scan now
	try reboot and check.
7. Try clean boot.
8. Do block inheritance.
9. Uninstall antivirus and check.
10. Run machine in safe mode and check if explorer.exe launches in safe mode.
11. Shell32.dll is binary on which explorer.exe works. Update shell32.dll (windows update).

Troubleshooting steps for spooler taking high CPU:
1. Run Print and Perf MSDT.
2. Do a print Hive Cleaning.
3. Use process explorer tool to check 3rd party threads (Advanced task manager).Rename 3rd party threads to .old.
4. Try clean boot.
5. Take the dump of spooler process using procdump tool. Always take 3 dumps.

Troubleshooting steps for Desktop Wallpaper not working:
1. Check how customer is deploying wallpaper GPO/GPP/Manually/Logonscript.
2. If customer is using GPO then check the policy setting and path of the wallpaper.
3. Check if wallpaper GPO is getting applied on the client by rsop and gpresult. If the policy is not getting applied then first engage DS team to troubleshoot the gpo issue. If policy is getting applied the follow next step.
4. Check the following registry location and verify if that it is the same path you mentioned in gpo
HKEY_CURRENT_USER\Software\Microsoft\Windows\Currentversion\Policies\System\Wallpaper
HKEY_CURRENT_USER\Software\Microsoft\Windows\Currentversion\Policies\System\Wallpaperstyle
5. If the customer is using UNC path then try to access the file from client machine using UNC path and wallpaper should open.
6. If the file is not accessible from client using UNC path. This means the file is not accessible when we try to login check the share permissions on wallpaper folder.
7. UNC path puts a lot of stress on network as it has to download file every time the wallpaper is loaded. It also means that I the network path cannot be contacted when the user logs on all they will get a black background wallpaper. So aply the below policy on the computer you are trying to login with the user and test if the policy applies. Policy Path: computer configurationàAdministrative templatesàsystemàlogonàalways wait for the network at computer startup and logon.
8. If the file is accessible from UNC path and still wallpaper is not deployed through group policy then copy the wallpaper on the client machine and manually set the file as desktop wallpaper and check if it applies.
9. If it applies then remove the manual wallpaper and keep the file on the client machine and give the local path in GPO and then ask the user to login.
10. Try to change the wallpaper and then try to login. The best way to identify which style is suitable for OS is to apply the wallpaper manually and check which default style it takes.
11. If the customer is using local path make sure the file is present on the local path of the client machine.
12. Try changing the wallpaper and check if it applies. 

 Troubleshooting steps for Unable to Print from Redirected Printer:
1. Check if printer is redirected (or) not.
2. Check the error message while printing.
3. Check if the easy print driver is in use.
4. Use generic text driver on client machine printer and then redirect the printer in the RDP session and see if you are able to print.
5. If it works with generic text (update the printer driver on client machine which is not compatible with easy print).
6. If generic text does not work update tsprint.dll on server (windows update) tsprint.dll is a dll for easy print driver.
7. If there is no update available for client printer driver educate the customer to use the same driver on server  he can do this by disabling the policy “ use easy print driver first”, this will ensure the faulty printer will use its own drivers and rest printers will still use easy print driver.
8. Try to update all printer binaries on client and server machines.
9. Print hive cleaning on both server and client.
10. Run perf and print MSDT.

Troubleshooting steps for Start Menu/Cortana not working in win 10:
1. Scope: àDetermine the kind of failure or what is not behaving as expected.
                           à Is start menu not working at all?
                           à Is start menu delayed or intermittent?
                           à Is cortana not starting?
                           à Is there an issue with tiles?
                          à Are any of the core processes crashing?
2. Checking Event Logs :
	
l Open event viewer , select show analytic and debug logs under view menu
l Examine admin, operational and diagnostics logs under the following entries if they are available
l Look for application crashes or events 1000 or 1001for shellexperiencehost.exe,sihost.exe and explorer.exe
		 
· System logs
· Application logs
· Microsoft\widows\shell-core
· Microsoft\windows\apps\microsoft-windows\Twinui
· Microsoft\windows\AppReadiness
· Microsoft\windows\AppXDeployement
· Microsoft\windows\AppxDeployement-server
			
3. Verify that the APPX package for the shellexperiencehost (or) cortana is installed in the following folders : C:\windows\systemapps 
	
·  ShellExperienceHost-cw5n1H2tyewy
· Micosoft.windows.cortana-cw5n1h2txyewy
· Contact support- cw5n1h2txyewy
· If these packages are not installed, you can check                                                                Microsoft_windows_appxdeployementserver_operational event log for errors or events on the app that has problem.  
	
4.  Checking the following registry , check if the entries are missing for all APPX packages
	 Here are the package names:
	HKEY_CLASSES_ROOT\Local_settings\software\microsoft\windows\current version\Appmodel\Repository\families
	Start menu is managed by a universal modern apps called shellexperiencehost.exe , this is a modern app in APPX format. Any setting to disable/block modern apps could impact start menu function and may make windows 10 not usable.
	
5. Ensure firewall service is started and firewall is enabled (ensure firewall is not disabled by a gpo)
	
6. Install all the APPX  packages using the following commands :
·  Get-appxpackage -all *shellexperience* -packagetype bundle |% {add-appxpackage -register -disabledevelopmentmode ($_.installlocation + “\appxmetadata\appxbundlemanifest.xml”)}
	 
· Get-AppXPackage -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	
7. Ensure machine is in clean boot
	
8. Check if disjoining the machine from the domain resolves the issue. If yes, rejoin the machine and if the issue happens after you join the machine back to domain. Move the machine to new OU and do block inheritance and test if the issue still happens. After doing block inheritance if the issue persists then run the above command (step6) to install all appx packages.
	
	
9. Check if recreating the user profile resolves the issue.
	
10.  For cortana issue, ensure [ HKEY_CURRENT_USER\software\microsoft\windows\current version\search] exists. If more than one user or machines are impacted, verify that the key exists in the default user profile (ntuser.dat). if it is missing from the default user profile then it will likely be missing from all newly created profiles.
	
11. When issue was happening for specific user delete the below file and check if start menu is working again:    (%localappdata%\microsoft\windows\usrclass.dat)
	
12. Please make sure “ALL APPLICATION PACKAGES”  is added and has permissions on  following locations:
	
·  C:\windows
· C:\program files
· C:\program files(x86)
· C:\users\%username%\appdata\local\microsoft\windows\wer
		
	Registry Paths:
	
· HKEY_CLASSES_ROOT
· HKEY_LOCAL_MACHINE\Drivers
· HKEY_LOCAL_MACHINE\Hardware
· HKEY_LOCAL_MACHINE\SAM
· HKEY_LOCAL_MACHINE\Software
· HKEY_LOCAL_MACHINE\System
· HKEY_USERS
		
13. Take procmon at the time of issue and investigate.

Troubleshooting steps for WMI DOWN Issue:
1. Check WMI is up in wmimgmt.msc and check if DCOM is up.
2. Check if local (or) Remote WMI is down.
3. Make sure WMI service is up and running.
4. Check if user has appropriate rights and permissions on the machines and wmi namespaces.
5. Run below command and check if WMI comes up:
	 WINMGMT  /VERIFYREPOSITORY (performs a consistency check on the WMI repository)
	
	WINMGMT  /SALVAGEREPOSITORY (performs a consistency check on the WMI repository and if an inconsistency is detected it rebuilds the repository) 
	
	WINMGMT  /RESETREPOSITORY(The repository is reset to thee initial state when th operating system is first installed .of files restored)
	
6. Run for commands to rebuild repository.
7. Collect WMIDIAG logs, WMI spy logs and WMI verbose logs
	 For WMI verbose logs:
	Navigate to HKEY_LOCAL_MACHINE\software\microsoft\wbem\cimom
	Set the logging value to appropriate level:
	0: no logging
	1: Errors only (default)
	2: verbose
	The default location for the log file is: C:\windows\system32\wbem\logs
	
8. Import WBEM folder from working machine after taking backup. Consult your tech lead before doing this step.

Troubleshooting steps for Unable to Run Task in Task Scheduler:
1. Check Task Scheduler services (svc host) are running or not and in the proper service account (local system account).
2. Check the history of task scheduler to check why the task did not run.
3. Check if you are able to run task manually.
4. Create a basic task to launch notepad and check if it launches, to verify task schedule engine.
5. Verify the task customer is running requires an interactive session or not.
6. Check the user account you are using to run the task has proper permission to run the task.
7. Recreate the task and check if it runs.

Troubleshooting steps for DCOM DOWN Issue:
1. Ensure the below services are up and running in their correct service account
·  COM + Event System – account local service
· COM + System Application-account local system
· DCOM server process launcher-account local system
· Distributed Transaction Co-ordinator-account network service
· Remote procedure call (RPC)- account network service
	
2. If MSDTC(distributed transaction coordinator) is not started or working, then no need to troubleshoot com+ or dcom at  this point. Engage setup or HA team to get this resolved with msdtc.
3. Ensure that Enable “Distributed COM on this computer “ is enabled 
	 Default authentication level is set to connect
	Default impersonation level is set to identify
	
4. Ensure default access and default launch and activation permissions are correct. Cross check the permissions from working machine.
5. Check the following registry location:
	 HKLM\software\microsoft\OLE  
	 EnableDcom  REG_SZ  Y
6. Delete machine access restriction and machine launch restrictions from the above registry key and reboot the server.
7. Merge OLE key from working machine.
8. Ensure below group policy are not applied computer configurationàsecurity settingàlocal policyàsecurity options
	 DCOM machine access restriction
	 DCOM machine launch restriction
	
9. If the below policy were applied then remove the policy and delete the below registry
	HKEY_LOCAL_MACHINE\software\policies\microsoft\windowsNT\DCOM 
	 Machine access restriction
	 Machine launch restriction

Troubleshooting steps for Unable to Install MSI package:
1. Check the error message while installing msi package.
2. Make sure windows installer service is running.
3. Install  basic msi package eg: mbsa to check if installer engine is up and running, if basic msi package is installing successfully then inform customer that windows  installer is not an issue and to contact the application vendor to further troubleshoot.
4. Check if WMI DCOM are up and running.
5. To ensure there are no problems with permissions or a corrupted file, have the customer create a new user account and add it to the local administrators group, use this account to install msi locally if the msi works with new administrator user/profile, recreate the user profile and test if this resolves the issue.
6. Re-register  msi engine
	Open cmd and navigate to c:\windows\system32 
	Run the below command
	Msiexec  /unregister
	Msiexec  /register
7. Clean boot and block inheritance
8. Ensure latest windows updates are installed
9. Try replacing following registry  keys from a similar working os and restart
	 [HKEY_LOCAL_MACHINE\software\microsoft\windows\current version\installer]
	 [HKEY_LOCAL_MACHINE\system\currentcontrolset\services\msiserver]
10. Enable windows installer logging by adding registry entries
	HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\installer
	REG_SZ: logging
	Value:  voicewarmupx
	Log location: “%temp%\msi????.log”

Basic Troubleshooting Steps for Temp Profile in UPD:
1. Check if UPD shared folder is accessible manually.
2. Check the share permission for everyone read access and check share and security permission and make sure all the session host is having full control.
3. Use sidder and find out if the upd is already in use for the particular user.
4. If the upd is already in use then try to find out where the upd is used you can do this using following :
		i. Creative use of shared with column when viewing the upd location.
		ii. Another option is to use startàRunàcompmgmt.mscàsystem toolsàshared foldersàopen file server where upd files are stored.
5. Once you find out of which server the upd is in use. Go on to that server and unmounts upd and now check with login
6. Disable UPD from collection properties and try to login to the server and check if there is local profile created or not. If the local profile is not created then UPD is not the issue. First resolve the local profile issue and then check by enabling upd and then try to login.
7. Try to find out if the temp profile issue is only with particular server in the collection or all servers. We can do this by moving all servers to drain mode and keeping one server in normal mode and check on what server temp profile is created.
8. Check the event at the time of issue on Session Host, Connection Broker and file server where UPD’s are stored.
9. If the issue is still not getting resolved then check with TL and collect further traces.


Basic Troubleshooting Steps from RDP via RDG:
1. Check the error message while rdp via rdg.
2. Check if internal RDP is working fine. If Internal RDP is not working then resolve the internal rdp issue first and then check with external rdp.
3. Ping the external name from external client machine and heck if it’s successful.
4. Telnet the external IP address from external client machine on port 3389 and check if it connects.
5. Check if remote desktop gateway service is up and running.
6. On remote computer gateway manager check CAP and RAP policy and make user users and computers are allowed on gateway server.
7. Check if certificate requirements are met on gateway server and check if correct certificate is binded.
8. Check event in event viewer of gateway server. You will check in application and services logàMicrosoftàwindowsàTerminal server gateway.
9. Recreate CAP and RAP policy. Check if it works.


WINRM (local and remote functionality)
Local functionality:
· Command to locate local listener and addresses. If no output is produced then winrm is not likely installed.
	Wimrm e winrm /config /listener
	
· Command to determine if the service is running and listener is functioning locally
	Winrm id
	
· From a command prompt to check state of configuration settings
	Winrm get winrm  /config
	
· From a command prompt to check the state of winrm service
	Winrm get wmicimv2 /win32_servicename = winrm
	
· From a command prompt to check more advanced functionality by using wirm and wmi to pull information aout the local operating system
	Winrm get wmicimv2 /win32_operating system

Remote functionality:
· The  –r parameter is used to specify a remote target machine. Note, when specifying remote machine the following are valid for this parameter:  local host,  net bios name, FQDN, and IP address
	
· From a command prompt to determine if the service is running and the listener is functioning remotely on a server:
	Winrm id –r: machinename
	
· From a command prompt  to check state of configuration settings on a remote machine
	Winrm get winrm /config –r: machinename
	
· From a command prompt to check the state of winrm service:
	Winrs –r: <machinename> dir  
	
· From a command prompt to check more advanced functionality by using winrm and wmi to pull information about the remote operating system:
	Winrm get wmicimv2 /win32_operating system -r : <machinename>
	
· This command deletes all listener effectively turning off winrm communication:
	Winrm invoke restore winrm /config@ {}
