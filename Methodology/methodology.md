Methodology

Scanning

if vulnhub

	- nmap -v -p- <target_ip> -oN nmap_initial_scan.txt
	- extract_open_ports.sh
	- nmap -v -p <open_Ports> -sC -sV -A -O <target_ip> -oN nmap_service_scan.txt

if Hack the Box

	- nmap -v -p- --min-rate 1000 <target_ip> -oN nmap_initial_scan.txt
	- nmap -v -p <ports_identified> -sCV -A <target_ip> -oN nmap_service_scan.txt

Enumeration

Port 80 443 HTTP and HTTPs

	- initial scanning and enum
		- first thing is to visit the page and see what's running

		- use searchploit and web for finding version exploit

		- while looking at the webpage do the following things

			- run nikto
				- nikto -h <target_ip>

			- run gobuster or feroxbuster
				- gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u <target_url> -t 50 -b 503,404
				- feroxbuster -u <target_url>

			- run dirsearch
				- dirsearch <target_url>

			- run fuff
				- ffuf -u http://usage.htb/ -H 'Host:FUZZ.usage.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac

			- run whatweb
				- whatweb <target_url>

			- run cmseek
				- cmseek <target_url>


	- if wordpress found

		- wpscan --disable-tls-checks --url <target_url> --enumerate ap,at,cb,dbe --plugins-detection aggressive -o wpscan_initial.txt
		- wpscan --url http://192.168.29.213/wp-login.php --password-attack wp-login --usernames username.txt --passwords <path_to_list>
		- proceed with wpscan -h (for dumping or cracking password)

	- if drupal found
		- use droopscan 
		- droopescan scan -u <taregt_url>
		- more on droopescan -h 

	- if joomla
		- joomscan -u <target_url>
		- more on joomscan -h



Port no 389 or 636 LDAP

	initial scanning and enum
		- use nmap script 
			- nmap -v -p 389,636 -sT -sV --script=ldap-search.nse <target_ip> -oN nmap_ldapsearch.txt
			- nmap -v -p 389,636 -sT -sV --script=ldap-rootdse.nse <target_ip> -oN nmap_rootdse.txt
			gather the information form this such as what is the dc name and if it gives the username note it down.


		- use ldapsearch for more enum
			- ldpasearch -x -H ldap://<target_ip>
			- ldapsearch -x -H ldap://<target_ip> -s base
			- ldapsearch -x -H ldap://<target_ip> -s sub
			- ldapsearch -x -H ldap://<target_ip> -s base -b "dc=domain,dc=name" (pass the domain name gathered from above enum)
			- ldapsearch -x -H ldap://<target_ip> -s sub -b "dc=domain,dc=name" (pass the domain name gathered from above enum)
			- ldapsearch -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "(&(objectclass=user))" -h 10.10.10.10 | grep -i samaccountname: | cut -f 2 -d " "
			# from the above commands and output files search for passwd user description and other things to gather more information.
			# note down the user and password and other information clearly

		- base64 password decode
			- echo -n <hash> | bse64 -d



Port no 139 or 445 SMB

		- nmap scripts to run on ad = smb-security-mode.nse [it will be enabled or disabled]

		- enum4linux
			- enum4linux -a <target_ip>
			
			# dump interesting  information
				- enum4linux -a [-u "<username>" -p "<passwd>"] <IP>
				- enum4linux-ng -A [-u "<username>" -p "<passwd>"] <IP>

		- smbclient
			- smbclient --no-pass -L //<IP>
			- smbclient --no-pass //<IP>/<Folder>
			- smbclient -U 'username' -L //<IP>
			- smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP> #If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash
				#Use --no-pass -c 'recurse;ls'  to list recursively with smbclient
			- smbclient -U '%' -N \\\\<IP>\\<SHARE> # null session to connect to a windows share
			- smbclient -U '<USER>' \\\\<IP>\\<SHARE> # authenticated session to connect to a windows share (you will be prompted for a password)

			NT_STATUS_PASSWORD_MUST_CHANGE then
			- smbpasswd -h 
			- smbpasswd -r <target_ip> -U '<username>'
			- smbpasswd -D 3 -r <target_ip> -U '<username>'

		- smb server version script
			- https://github.com/rewardone/OSCPRepo/blob/master/scripts/recon_enum3/smbver.sh

		- smbmap [connecting to smb]
			- smbmap -H <IP> [-P <PORT>] #Null user
			- smbmap -u "username" -p "password" -H <IP> [-P <PORT>] #Creds
			- smbmap -u "username" -p "<NT>:<LM>" -H <IP> [-P <PORT>] #Pass-the-Hash
			- smbmap -r -u "username" -p "password" -H <IP> [-P <PORT>] #Recursive list
			- smbmap [-u "username" -p "password"] -R [Folder] -H <IP> [-P <PORT>] # Recursive list
			- smbmap [-u "username" -p "password"] -r [Folder] -H <IP> [-P <PORT>] # Non-Recursive list
			- smbmap -u "username" -p "<NT>:<LM>" [-r/-R] [Folder] -H <IP> [-P <PORT>] #Pass-the-Hash
			
			- smbmap -u <username> -p 'ntlm hash:lm hash' -H <target ip>
			- smbmap -u <username> -p 'ntlm hash:lm hash' -H <target ip> -r [recursive switch for listing contents]
			- smbmap -u <username> -p 'ntlm hash:lm hash' -H <target ip> -r alice [share we want to use for recursive switch]
			- smbmap -u <username> -p 'mtlm hash: lm hash' -H <target_ip> --download <file path> [to download content from share]

		- convert .ppk to .pem 
			- apt-get install putty-tools
			- puttygen ppkkey.ppk -O private-openssh -o pemkey.pem
			# .pem to .ppk
			- puttygen pemKey.pem -o ppkKey.ppk -O private

	when we have the password
		- Command Execution on Smb using psexec
			- impacket-psexec <domain name>/<username>:<password>@<target_ip> <command>
				- impacket-psexec armourinfosec.local/sachin:@rmour123@192.168.29.100 ipconfig

			- more on https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb#execute-commands

	when we don't have the passwords
		# list to use /usr/share/seclists/Passwords/500-worst-passwords.txt | /usr/share/seclists/Passwords/darkweb2017-top100.txt
		# now we have to brute force smb [tool we will use ic crackmapexec]

		SMB
			- sudo crackmapexec smb <targetip> -u <username or list> -p <password or list> --continue-on-success
			- sudo crackmapexec smb 10.10.10.10 -u username -p pass -M spider_plus --share 'Department Shares' 
				- -M spider_plus [--share <share_name>]
				- --pattern txt

		Winrm
			- sudo crackmapexec winrm 192.168.29.100 -u monah.bonita -p hello --continue-on-success
			- sudo crackmapexec winrm 192.168.29.100 -u smbusers.txt -p password1.txt --continue-on-success | grep '(Pwn3d!)'
			- sudo crackmapexec winrm 192.168.29.100 -u smbusers.txt -p /usr/share/seclists/Passwords/darkweb2017-top100.txt --continue-on-success | grep '(Pwn3d!)'
			- sudo crackmapexec winrm 192.168.29.1/24 -u monah.bonita -p hello [this will login the users to every pc which is running winrm on it]


Port no 5985 or 5986 Winrm

	- Utility used to run commands on windows machine and get shell access

	- Tool used = evil.winrm
		- download link https://github.com/Hackplayers/evil-winrm
	- evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!'  
	- evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/' [-s can be used to run scripts] 


Port Number 88 Kerberos

	- first we will try to get the principal names from ldapsearch command which we have previously used.
		- ldapsearch -x -H ldap://192.168.29.100 -s sub/base -b "dc=domain,dc=name" | grep userPrincipalName: | cut -d " " -f 2 > userPrincipalName.txt
		- ldapsearch -x -H ldap://192.168.29.100 -s sub/base -b "dc=domain,dc=name" | grep sAMAccountName: | cut -d " " -f 2 > sAMAccountName.txt
		- ldapserach -x -H ldap://192.168.29.100 -s sub/base -b "dc=domain,dc=name" | grep servicePrincipalName: | cut -d " " -f 2 > servicePrincipalName.txt

	- using impacket-GetUserSPNs https://wadcoms.github.io/wadcoms/Impacket-GetUserSPNs/
		- impacket-GetUserSPNs domain/username:password -dc-ip <target_ip>
		- impacket-GetUserSPNs armourinfosec.local/monah.bonita:hello -dc-ip 192.168.29.100
		# this will give us the list of services

		- impacket-GetUserSPNs domain/username:password -dc-ip <target_ip> -request
		# this will give us the hashes of the services. 

		# refer hashcat to crack the hash






Hash Cracking

	- finding hash type 
		- hashcat --example-hashes | grep <hash>
		- hash-identifier
			enter hash it will give the posible hash format.

		- hashcat -h | grep <hashtype> [to look for the hash number which is used in the next command]

		- hashcat -m 1800 -a 0 <path/to/hash> <path/to/rockyou> 


	- kerberos hash crack
		- hashcat --help | grep kerberos
		- hashcat -m 13100 [or mode which you want] -a 0 <path/to/hash> <path/to/rockyou>


In windows there are 4 ways to execute commands

1. Remote Desktop [3389]
2. Smb [139 445]
3. Telnet [23]
4. Winrm [5985 5986(secure)]
