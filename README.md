# Create Your Custom UTM with Your Old Server

## 1. Choose a Lightweight Linux Distribution

**Recommended OS**:
- **Debian** or **Ubuntu Server** (minimal installation)
Both distributions are stable and widely supported by the community, making them ideal for setting up your UTM.

---

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

### Adding Custom Rule to IDS/IPS
```bash
freeutm --configure --ids/ips --add-rule '<rule>'   # Add new rule to local.rules
```

### Antivirus Configuration (ClamAV, Maldet, RKhunter, chkrootkit, Yara)
```bash
freeutm --configure --av   # Configure ClamAV, Maldet, RKhunter, chkrootkit, and Yara
```

### Update Antivirus Database
```bash
freeutm --configure --av --update   # Update antivirus database
```

### Monitoring Configuration (Netdata)
```bash
freeutm --configure --monitoring   # Configure Netdata for system monitoring
```

### System Hardening
```bash
freeutm --configure --hardening   # Harden system security settings
```

---

## 3. General Help
If you need additional guidance or help with commands, use the following:
```bash
freeutm --help   # Display help information
```

---

With these steps, you can set up a comprehensive UTM solution tailored to your server's needs. Each configuration command enhances your server’s security and monitoring capabilities.
