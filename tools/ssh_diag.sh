#!/bin/bash

if [[ ( $@ == "--help") ||  $@ == "-h" ]]; then
	    echo "Usage: $0 ssh_login_id ssh_principal"
	        echo "Example: $0 ubuntu foo.bar"
		    exit 0
fi
if [  $# -le 1 ]; then
	    echo "Usage: $0 ssh_login_id ssh_principal"
	        echo "Example: $0 ubuntu foo.bar"
		    exit 1
fi

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`

# Detect OS
os=`lsb_release -si`
printf "${green}Running system diagnostics${reset}"
printf "\n*** General system details ***\n"
echo "Operating system: $os"
echo "Current time: $(date)"
ssh -V
echo "SSH service status:"
service sshd status | grep -i active
echo "System memory available: $(free -m | awk '/^Mem:/{printf("%.1fGb\n",$7/1000)}')"
#Check certificate based auth config in sshd_config
printf "\n*** SSH configuration file ***\n\n"
grep "TrustedUserCAKeys" /etc/ssh/sshd_config
grep "AuthorizedPrincipalsFile" /etc/ssh/sshd_config
echo "SSH config file was last modified on: $(date -r /etc/ssh/sshd_config)"
#Check auth_principals dir
printf "\n*** Auth principals directory check ***\n"
if [ -d "/etc/ssh/auth_principals" ] 
then
    printf "\nChecking auth_principals directory: ${green}PASS\n${reset}" 
else
    printf "\nChecking auth_principals directory: ${red}FAILED\n${reset}" 
fi
#Check ca_cert.pub 
printf "\n*** Trusted user CA keys check ***\n"
if [ -e "/etc/ssh/ca_cert.pub" ]
then
    printf "\nChecking ca_cert.pub: ${green}PASS\n${reset}"
else
    printf "\nChecking ca_cert.pub: ${red}FAILED\n${reset}"
fi
if [ $# -eq 2 ]
  then
	printf "\n*** Auth principal name check ***\n"
	if [ -e "/etc/ssh/auth_principals/$1" ]
	then
    		printf "\nAuth principals file detection for user $1: ${green}PASS\n${reset}"
	else
    		printf "\nAuth principals file detection for user $1: ${red}FAILED\n${reset}"
    		exit 1
	fi
	for f in /etc/ssh/auth_principals/$1
	do
		#Check if user to auth principal mapping is correct
		if grep -wiq $2 "$f"; then
	        	printf "User to auth principals mapping: ${green} PASS ${reset}"
		else
			printf "User to auth principals mapping: ${red} FAILED ${reset}"
        	fi
		#Check if auth principal files contain domain names
		if grep -irql @ "$f"; then
			printf "\nAuth principal detected for user `basename $f` ${red}is INVALID \n${reset}"
			printf "${red}--Error: make sure the principal name in cert matches the principal in $f\n${reset}"
		fi
	done
	printf "\n\n*** Authentication logs for user $1/$2 ***\n"
    	tail -10 /var/log/auth.log | grep $1
    	tail -10 /var/log/auth.log | grep $2
fi
printf "\n${green}*** Diagnostics completed ***\n${reset}"
