#!/usr/bin/python

#############################################
#
# Local user migration to LDAP based accounts

import ldap
import os
import pwd
import grp
import re
import smtplib
import email.mime.multipart
import email.mime.text
import email.mime.base
import sys
import shutil
import subprocess


exclude_dirs=['/var/lib/sudo','/var/db/sudo','/var/spool/mail','/proc']
exclude_users=[]
min_uid=1000



#############################################
# get_local_users():
# Gives back a directory containing local users (definied in /etc/passwd) whom uidNumber is higher than / or equal min_uid
# Each entry in the directory is a list containing uidNumber,gidNumber,homeDirectory referenced by uid

def get_local_users():
	local_users={}
	with open ('/etc/passwd','r') as passwd:
		for line in passwd.readlines():
			luser=[]
			passwd_user=line.rstrip('\n').split(':')
			if int(passwd_user[2]) >= min_uid:
				luser.append(passwd_user[2])
				luser.append(passwd_user[3])
				luser.append(passwd_user[5])
				local_users[passwd_user[0]]=luser
	return local_users

#############################################
# get_ldap_config():
# Gathers the ldap config parameters from /etc/nslcd.conf, and gives it back as a dictionary

def get_ldap_config():
	ldap_config={}
	with open ('/etc/nslcd.conf','r') as nslcd:
		for line in nslcd.readlines():
			if not(line.find('uri')):
				if not(ldap_config.has_key('uri')):
					ldap_config['uri']=line.rstrip('\n').split(' ')[1]
			if not(line.find('binddn')):
				ldap_config['binddn']=line.rstrip('\n').split(' ')[1]
			if not(line.find('bindpw')):
				ldap_config['bindpw']=line.rstrip('\n').split(' ')[1]
			if not(line.find('base')):
				ldap_config['base']=line.rstrip('\n').split(' ')[1]
			if not(line.find('filter passwd')):
				ldap_config['filter']=line.rstrip('\n').split(' ')[2]
		
	return ldap_config

#############################################
# get_ldap_users():
# Returns a dictionary of the LDAP users allowed on the host whom has a unix user name in their description
# Dictionary referenced by the unix user name contains a list with the LDAP uid,uidNumber,gidNumber,homeDirectory

def get_ldap_users():
	ldap_config=get_ldap_config()
	try:
		ldap_con=ldap.initialize(ldap_config['uri'])
		ldap_con.start_tls_s()
		ldap_con.simple_bind_s( ldap_config['binddn'],ldap_config['bindpw'])
		ldap_search=ldap_con.search_s(ldap_config['base'],ldap.SCOPE_SUBTREE,ldap_config['filter'],['uid','uidNumber','gidNumber','homeDirectory','description'])
	except Exception as err:
		print "Oops"
		print err.args
	finally:
		ldap_users={}
 		for i in range(len(ldap_search)):
			luser=[]
			luser.append(ldap_search[i][1]['uid'][0])
			luser.append(ldap_search[i][1]['uidNumber'][0])
			luser.append(ldap_search[i][1]['gidNumber'][0])
			luser.append(ldap_search[i][1]['homeDirectory'][0])
			if ldap_search[i][1].has_key('description'):
				desc=ldap_search[i][1]['description'][0].split('\r\n')
				for k in range(len(desc)):
					if not(desc[k].find('unix:')):
						uname=desc[k].split(':')[1]
						ldap_users[uname]=luser
		return ldap_users


#############################################
# get_processes():
# Returns a dictionary of processes owned by users with uid >= min_uid
# Dictionary referenced by the unix user name contains a list of list of pids and commandlines
def get_processes():
	proc=os.listdir('/proc')
	pids=[]
	processes={}
	for k in range(len(proc)):
		if proc[k].isdigit():
			pids.append( proc[k])
	for i in range(len(pids)):
		status_fname='/proc/'+pids[i]+'/status'
		cmdline_fname='/proc/'+pids[i]+'/cmdline'

		with open(status_fname,'r') as status_file:
			for line in status_file.readlines():
				if line.startswith('Uid:'):
					uid=line.split()[1]
	
		if int(uid) >= 1000:
			with open(cmdline_fname,'r') as cmdline_file:
				cmdline=cmdline_file.readlines()
		
			p=[pids[i],cmdline[0].rstrip('\x00')]
			uname=pwd.getpwuid(int(uid)).pw_name
			if processes.has_key(uname):
				processes[uname].append(p)
			else:
				processes[uname]=[p]
	return processes

#############################################
# get_cronjobs():
# Returns a dictionary of cronjobs owned by users with uid >= min_uid
# Dictionary referenced by the unix user name contains a list of list of cronfile, schedule and commandlines
def get_cronjobs():
	cronjobs={}

	crond=os.listdir('/etc/cron.d')
	crond_files=['/etc/crontab']
	for fname in crond:
		crond_files.append('/etc/cron.d/'+fname)

	for fname in crond_files:
		with open(fname,'r') as crond_file:
			for line in crond_file.readlines():
				if (not line.startswith('#')) & (not line.isspace()) & (re.search('^[0-9\*\/,].',line) is not None):
					uname=line.rstrip('\n').split()[5]
					if pwd.getpwnam(uname).pw_uid >= min_uid:
						job=[fname,line.split(uname)[0],line.split(uname)[1].rstrip('\n').lstrip()]
						if cronjobs.has_key(uname):
							cronjobs[uname].append(job)
						else:
							cronjobs[uname]=[job]
	cronf=[]
	if os.path.exists('/var/spool/cron/crontabs'):
		cronf=os.listdir('/var/spool/cron/crontabs')
		crondir='/var/spool/cron/crontabs/'
	else:
		if os.path.exists('/var/spool/cron'):
			cronf=os.listdir('/var/spool/cron')
			crondir='/var/spool/cron/'


	for uname in cronf:
		if pwd.getpwnam(uname).pw_uid >= min_uid:
			crontab_fname=crondir+uname
			with open(crontab_fname,'r') as crontab_file:
				for line in crontab_file.readlines():
					if (not line.startswith('#')) & (not line.isspace()) & (re.search('^[0-9 \* \/].',line) is not None):
						job=[crontab_fname,line.split(line.split(' ',5)[5])[0],line.split(' ',5)[5]]
						if cronjobs.has_key(uname):
							cronjobs[uname].append(job)
						else:
							cronjobs[uname]=[job]

	return cronjobs


def get_report():
	ldap_users=get_ldap_users()
	local_users= get_local_users()
	processes=get_processes()
	cronjobs=get_cronjobs()
	report=''
	
	for key in local_users:
		if not(key in exclude_users):
			if not(os.path.exists(local_users[key][2]+'/.ldap_mig')):
				error=False
				if ldap_users.has_key(key):
					report+=key+'\t==> '+ldap_users[key][0]+'\n'
					if processes.has_key(key):
						error=True
						report+='Following processes are running in the name of the user:\n'
						for pid in  processes[key]:
							report+=pid[0]+'\t'+pid[1]+'\n'
					if cronjobs.has_key(key):
						error=True
						report+='\nFollowing cronjobs running in the name of the user:\n'
						for job in cronjobs[key]:
							report+=job[0]+'\t'+job[1]+'\t'+job[2]+'\n'
					if error:
						report+='ERROR: user has to be migrated manually\n'
				else:
					report+=key+'\nERROR: has no ldap user matched\n'
				report+='===================================================================\n'
		
	return report

def migrate_user(uname,user_local,user_ldap):
#Cheking if there are processes running in the name of the user if yes tehn abort
	print 'Checking for processes'
	processes=get_processes()
	if processes.has_key(uname):
		print 'Thre is processes running in the name of the user, unable to migrate'
		for pid in  processes[uname]:
			print pid[0]+'\t'+pid[1]
		return False
#Cheking if there are cronjobs with the name of the user if yes, then abort
	print 'Checking for cronjobs'
	cronjobs=get_cronjobs()
	if cronjobs.has_key(uname):
		print 'Thre are cronjobs running in the name of the user, unable to migrate'
		for job in cronjobs[uname]:
			print job[0]+'\t'+job[1]+'\t'+job[2]
		return False
#Creating the new home directory by copying the old one. If the new directory
#already exist, then abbort
	print 'Creating new home directory '+user_ldap[3]+' and copying files'
	if os.path.exists(user_ldap[3]):
		print 'User home directory already exists unable to migrate'
		return False
	else:
		command=['/bin/cp','-a',user_local[2],user_ldap[3]]
		subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE).wait
#searching for files on the system with the user local uid and gid
	print 'Searching for user files'
	command=['/usr/bin/find','/','-uid',user_local[0],'-o','-gid',user_local[1]]
	p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output, error =p.communicate()
	if output:
		find_files=output.split('\n')
	else:
		find_files=[]
	user_files=[]
#cheking if the files are excluded
	exclude_dirs.append(user_local[2])
	for fname in find_files:
		if fname:
			not_excluded=True
			for directory in exclude_dirs:
				if os.path.commonprefix([fname,directory])==directory:
					not_excluded=False
			if not_excluded:
				user_files.append(fname)
#Changeing the local uid and gid to the ldap ones					
	print 'Found '+str(len(user_files))+' files to migrate'
	for fname in user_files:
		uid=os.stat(fname).st_uid
		gid=os.stat(fname).st_gid
		if uid==int(user_local[0]):
			uid=int(user_ldap[1])
		if gid==int(user_local[1]):
			gid=int(user_ldap[2])
		print 'Changeing ownership of file: '+fname+' to '+pwd.getpwuid(uid).pw_name+':'+grp.getgrgid(gid).gr_name
		os.lchown(fname,uid,gid)
#Creating a file with the ldap usernam in the local user directroy to marked as migrated
	fname=user_local[2]+'/.ldap_mig'
	with open(fname,'w') as f:
		f.write(user_ldap[0])
		


###########
## Main ###
###########



# Set min_uid from /etc/login.defs
with open('/etc/login.defs','r') as login_defs:
	for line in login_defs.readlines():
		if line.startswith('UID_MIN'):
			min_uid=int(line.lstrip('UID_MIN'))
	

#If no argument generate report
if len(sys.argv)==1:
	rep=get_report()
	if len(rep)==0:
		print 'Nothing to report'
	else:
		print rep
	sys.exit()

#If the first argument is mail send it to the given e-mail address
if (len(sys.argv)==2) and (sys.argv[1]=='mail'):
	print 'Pleae supply a coma separated list of e-mail addreses'
	sys.exit()
if (len(sys.argv)==3) and (sys.argv[1]=='mail'):
	reportaddr=sys.argv[2].split(',')
	for addr in reportaddr:
		if not(re.match('^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$',addr.lower())):
			print addr+' is not a valid e-mail addresses'
			sys.exit()
	rep=get_report()
	if len(rep)<>0:
		msg=email.mime.multipart.MIMEMultipart()
		msg.add_header('Subject',"[RePort][CentAuthMig]["+os.uname()[1]+"]")
		msg.add_header('From',"noreply@elephanttalk.com")
		msg.add_header('To:',",".join(map(str, reportaddr)))
		msg.attach(email.mime.text.MIMEText(get_report()))
		server=smtplib.SMTP('192.168.10.76')
		server.sendmail("noreply@elephanttalk.com",reportaddr,msg.as_string())
		server.quit()
	sys.exit()

#If the first argument is  migrate migrate the given user or all the users
if (len(sys.argv)==2) and (sys.argv[1]=='migrate'):
    print 'Missing username'
    sys.exit()
if (len(sys.argv)==3) and (sys.argv[1]=='migrate'):
	if sys.argv[2]=='all':
		print 'Migrate all users'
		local_users=get_local_users()
		ldap_users=get_ldap_users()
		for user_local in local_users:
			if not(user_local in exclude_users):
				if os.path.exists(local_users[user_local][2]+'/.ldap_mig'):
					print 'User '+user_local+' has been already migrated'
				else:
					if ldap_users.has_key(user_local):
						print 'Migrating user '+user_local
						print migrate_user(user_local,local_users[user_local],ldap_users[user_local])
					else:
						print 'Unable to find LDAP user for '+user_local+' either not mapped to any user, or not allowed on this host'
		sys.exit()
	else:
		local_users=get_local_users()
		if local_users.has_key(sys.argv[2]):
			if os.path.exists(local_users[sys.argv[2]][2]+'/.ldap_mig'):
				print 'User '+sys.argv[2]+' has been already migrated'
				sys.exit()
			else:
				ldap_users=get_ldap_users()
				if ldap_users.has_key(sys.argv[2]):
					print 'Migrating user '+sys.argv[2]
					print migrate_user(sys.argv[2],local_users[sys.argv[2]],ldap_users[sys.argv[2]])
					sys.exit()
				else:
					print 'Unable to find LDAP user for '+sys.argv[2]+' either not mapped to any user, or not allowed on this host'
					sys.exit()
		else:
			print 'Unable to find user: '+sys.argv[2]
			sys.exit()



