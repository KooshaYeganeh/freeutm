
## Create New Generation Firewalls with Old Servers



### Choose a Lightweight Linux Distribution

Recommended OS: Debian or Ubuntu Server (minimal installation).

Both are stable and have extensive community support.

#### Lubuntu

![Lubuntu](https://fosspost.org/wp-content/uploads/2019/09/lubuntu-19-04-review-6.png)

![Ubuntu Server](https://ubuntucommunity.s3.us-east-2.amazonaws.com/original/2X/1/17ee449b2bd7c530d2f996215407fca5b722dcb2.png)




### Configure Firewall

#### iptables



```
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # Allow SSH
sudo iptables -A INPUT -j DROP
iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min --limit-burst 5 -j ACCEPT
iptables -A INPUT -j LOG --log-prefix "Dropped: " --log-level 4
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
```
Save the rules:

```
sudo apt install iptables-persistent
sudo netfilter-persistent save
sudo netfilter-persistent reload
```


Avoid unnecessary rules: Keep the ruleset as simple as possible by avoiding redundant or unnecessary rules. Each rule adds overhead, so only add rules that are necessary for your use case.

Use -m conntrack for connection tracking: Instead of writing multiple rules for related connections, use -m conntrack to optimize for connection tracking. This avoids having multiple rules for the same connection.

Example:

```
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```
Use iptables sets: iptables allows you to define a set of IP addresses, ports, etc., and then refer to them in rules. This can be useful for managing large groups of IPs and reducing the number of rules.

Example:

```
ipset create myset hash:ip
```
```
ipset add myset 192.168.1.1
```
```
iptables -A INPUT -m set --match-set myset src -j ACCEPT
```
Use iptables chains effectively: Avoid excessive use of custom chains. While custom chains can be used to organize rules, they can sometimes add overhead. Use them judiciously.

Rule ordering: Place more commonly used rules at the top of the rule set to minimize processing time for matching packets.


#### iptables-save

```
iptables-save >/etc/iptables/rules.v4
```

```
sysctl -w net.netfilter.nf_conntrack_max=262144
```
```
sysctl -w net.ipv4.tcp_fin_timeout=30
```

```
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
```



### configure psad

```
sudp apt install psad
```

```
sudo psad --sig-update
sudo systemctl restart psad
```

```
sudo vi /etc/psad/psad.conf
```

sets:

```
ENABLE_AUTO_IDS Y;
AUTO_IDS_TCP_PORTS any;
AUTO_IDS_UDP_PORTS any;
```


### Configure ipset

```
ipset create blacklist hash:ip
ipset add blacklist 192.168.1.1
ipset add blacklist 192.168.1.2
iptables -A INPUT -m set --match-set blacklist src -j DROP

```


### Configure Fail2ban

```
sudo apt install fail2ban -y
```
```
cd /etc/fail2ban/
```
```
sudo cp jail.conf jail.local
```

```
sudo vi /etc/fail2ban/jail.local
```

```
ignoreip = 127.0.0.1/8 ::1 123.123.123.123 192.168.1.0/24
```

#### Whitelist IP Addresses

```
ignoreip = 127.0.0.1/8 ::1 123.123.123.123 192.168.1.0/24
```


#### Ban Settings

```
bantime  = 1d
findtime  = 10m
maxretry = 5
action = %(action_mw)s
```


#### Fail2ban Jails

```
[proftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(proftpd_log)s
backend  = %(proftpd_backend)s
```

```
[sshd]
enabled   = true
maxretry  = 3
findtime  = 1d
bantime   = 4w
ignoreip  = 127.0.0.1/8 23.34.45.56
```





### Configure Zeek

```
apt install curl gnupg2 wget -y
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list
apt update -y
apt install zeek -y
echo "export PATH=$PATH:/opt/zeek/bin" >> ~/.bashrc
source ~/.bashrc
zeek --version

```
url : https://www.howtoforge.com/how-to-install-zeek-network-security-monitoring-tool-on-ubuntu-22-04/


![bro-scripts](https://github.com/zeek/bro-scripts)
![bro-scripts2](https://github.com/michalpurzynski/zeek-scripts)


### Configure Snort

```
sudo apt install snort -y
```
```
sudo snort -c /etc/snort/snort.conf -i eth0
```


Enable custom rules:

Edit /etc/snort/snort.conf:

```
include $RULE_PATH/community.rules
```

Download community rules:

```
wget https://www.snort.org/downloads/community/community-rules.tar.gz
tar -xvzf community-rules.tar.gz -C /etc/snort/rules/
```

Test rules:

```
snort -c /etc/snort/snort.conf -T
```


Snort rule to trigger when an executable file is transferred over HTTP:

```
alert tcp any any -> any 80 (msg:"Executable file transfer"; flow:to_client,established; file_data; content:"MZ"; classtype:trojan-activity; sid:1000001;)
```

### Configure Maltrail

```
git clone https://github.com/stamparm/maltrail.git
```

```
sudo apt-get install git python3 python3-dev python3-pip python-is-python3 libpcap-dev build-essential procps schedtool
sudo pip3 install pcapy-ng
git clone --depth 1 https://github.com/stamparm/maltrail.git
cd maltrail
sudo python3 sensor.py
```



### Configure Clamav

```
sudo apt install clamav -y
```

```
0 2 * * * /usr/bin/clamscan --remove --recursive --infected / --exclude-dir="^/sys" --exclude-dir="^/proc" --log=/var/log/clamav-scan.log
```

### Configure Maldet

```
cd /tmp && wget http://www.rfxn.com/downloads/maldetect-current.tar.gz && tar xfz maldetect-current.tar.gz && cd maldetect-1.6.* && sudo ./install.sh && cd
```

```
#To enable the email notification.
email_alert="1"

# Specify the email address on which you want to receive an email notification.
email_addr="user@domain.com"

# Enable the LMD signature autoupdate.
autoupdate_signatures="1"

# Enable the automatic updates of the LMD installation.
autoupdate_version="1"

# Enable the daily automatic scanning.
cron_daily_scan="1"

# Allows non-root users to perform scans.
scan_user_access="1"

# Move hits to quarantine & alert
quarantine_hits="1"

# Clean string based malware injections.
quarantine_clean="0"

# Suspend user if malware found. 
quarantine_suspend_user="1"

# Minimum userid value that be suspended
quarantine_suspend_user_minuid="500"

# Enable Email Alerting
email_alert="1"

# Email Address in which you want to receive scan reports
email_addr="you@domain.com"

# Use with ClamAV
scan_clamscan="1"

# Enable scanning for root-owned files. Set 1 to disable.
scan_ignore_root="0"
```


```
sudo /usr/local/sbin/maldet --mkpubpaths
```


### Configire Rkhunter

```
sudo apt install rkhunter -y
```

Edit /etc/rkhunter.conf:

```
ALLOW_SSH_ROOT_USER=0
SCRIPTWHITELIST=/usr/bin/prelink
```

### Automate scans:

```
echo "0 3 * * * /usr/bin/rkhunter --check --cronjob --report-warnings-only" | sudo tee -a /etc/crontab
```

### Configure chkrootkit

```
sudo apt install chkrootkit -y
```


## netdata
https://wiki.crowncloud.net/?how_to_Install_netdata_monitoring_tool_ubuntu_22_04


### system Hardening

**Secure SSH**

> Before making any changes, always back up the SSH configuration files:

```
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
```

> Disable root login:

```
sudo vi /etc/ssh/sshd_config
```

```
PermitRootLogin no
```

> Use SSH Protocol 2 Only

```
Protocol 2
```

> Use Strong Authentication Methods

```
PasswordAuthentication no
```

> Disable Empty Passwords

```
PermitEmptyPasswords no
```

> Limit SSH Access to Specific Users or Groups

```
AllowUsers user1 user2
```

> Change the Default SSH Port

```
Port 2222
```

> add ssh Service to Fail2Ban

```
sudo vi /etc/fail2ban/jail.local
```

```
[sshd]
enabled = true
port = 2222  # Change this if you modified your SSH port
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600  # 1 hour
findtime = 600  # 10 minutes
```


> Enable SSH Banner

```
sudo vi /etc/issue.net
```
Add a message (for example):

```
Warning: Unauthorized access is prohibited.
```

> Enable the banner in /etc/ssh/sshd_config

```
Banner /etc/issue.net
```

---

Enable Automatic Updates

Install unattended-upgrades:

```
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure unattended-upgrades
```



