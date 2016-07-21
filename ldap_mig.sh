if [ -f ~/.ldap_mig ]
then
	user=`whoami`
	ldapuser=`cat ~/.ldap_mig`
	if [ $user != $ldapuser ]
	then
		echo "########################################################################"
		echo "#                !!!!! User has been migrated !!!!!               ######"
		echo "########################################################################"
		echo "Dear "$user
		echo "Your user has been migrated under the new central authorization schema"
		echo "You can now log in as: "$ldapuser" with your Sharepoint/Windows password"
		read -p "Press ENTER to continue......."
		echo ""
		echo "Login as "$ldapuser
		su -  $ldapuser
		logout
	fi
fi
