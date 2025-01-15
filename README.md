
## Create New Generation Firewalls with Old Servers



### Choose a Lightweight Linux Distribution

Recommended OS: Debian or Ubuntu Server (minimal installation).

Both are stable and have extensive community support.

#### Lubuntu

![Lubuntu](https://fosspost.org/wp-content/uploads/2019/09/lubuntu-19-04-review-6.png)

![Ubuntu Server](https://ubuntucommunity.s3.us-east-2.amazonaws.com/original/2X/1/17ee449b2bd7c530d2f996215407fca5b722dcb2.png)


### HELP

```
freeutm --configure --firewall # configure firewall tools
```                

```
freeutm --configure --kernel # configure Kernel Parameters
```         

```
freeutm --configure --service-manager # configure Fail2Ban 
```

```
freeutm --configure --ids/ips # configure Zeek and snort and maltrail
```


```
freeutm --configure --ids/ips --add-rule '<rule>' # add New rule for local.rules
```


```
freeutm --configure --av # configure clamAV and Maldet and RKhunter and chkrootkit and Yara
```                                      

```
freeutm --configure --av --update # Update Antivirus Database
```

```
freeutm --configure --monitoring # configure Netdata
```               

```
freeutm --configure --hardening # Hardening system
``` 

```
freeutm --help
```


