# Create Your Custom UTM with Your Old Server

## 1. Choose a Lightweight Linux Distribution

**Recommended OS**:
- **Debian** or **Ubuntu Server** (minimal installation)
Both distributions are stable and widely supported by the community, making them ideal for setting up your UTM.

---

**Note 1- First open Script and chnage Email Address with Valid Mail**





## 2. Configuration Commands

### Firewall Configuration
```bash
freeutm --configure --firewall   # Configure firewall tools
```

### Kernel Parameters Configuration
```bash
freeutm --configure --kernel    # Configure kernel parameters
```

### Fail2Ban Configuration
```bash
freeutm --configure --service-manager   # Configure Fail2Ban
```

### IDS/IPS Configuration (Zeek, Snort, Maltrail)
```bash
freeutm --configure --ids/ips   # Configure Zeek, Snort, and Maltrail
```

### Antivirus Configuration (ClamAV, Maldet, RKhunter, chkrootkit, Yara)
```bash
freeutm --configure --av   # Configure ClamAV, Maldet, RKhunter, chkrootkit, and Yara
```

### Monitoring Configuration (Netdata)
```bash
freeutm --configure --monitoring   # Configure Netdata for system monitoring
```

### System Hardening
```bash
freeutm --configure --hardening   # Harden system security settings
```

### Scan system with AV

```bash
freeutm --av --scan
```

### Update Antivirus Database
```bash
freeutm --av --update   # Update antivirus database
```

### check Vulnerability

```bash
freeutm --vulcheck 
```

### Adding Custom Rule to IDS/IPS
```bash
freeutm --ids/ips --add-rule '<rule>'   # Add new rule to local.rules
```


---

## 3. General Help
If you need additional guidance or help with commands, use the following:
```bash
freeutm --help   # Display help information
```

---

With these steps, you can set up a comprehensive UTM solution tailored to your server's needs. Each configuration command enhances your server’s security and monitoring capabilities.
