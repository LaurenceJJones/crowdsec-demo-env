## Demo scripts

This directory contains shell scripts that scaffold a demo environment for CrowdSec security engine and remediation components

Currently only tests on Debian based distributions are supported. Note nginx bouncer is not supported Ubuntu 22.04 and higher due to ubuntu maintainers dropping lua support.

### Usage

Environment init script will setup iptables, nginx and auditd. This **WILL NOT** install any CrowdSec components this is purely to setup the environment to log and block traffic.

**RUN BEFORE INSTALLING CROWDSEC SECURITY ENGINE**
```bash
./env-init.sh
```

**INSTALL CROWDSEC SECURITY ENGINE HERE**
[documentation](https://docs.crowdsec.net/docs/next/getting_started/install_crowdsec)

**RUN AFTER INSTALLING CROWDSEC SECURITY ENGINE**
This will setup the remediation components and parsers to work with the environment setup by the init script.

```bash
CONSOLE_ENROLL=XXXXXXX ./env-post.sh
```

If you wish to show 2 way decisions from the console simply provide your console enrollment token to the `env-post.sh` script.

### Demo scenarios

Here are the scenario that are currently supported by the demo scripts and how to trigger them

#### Port scan

Download Nmap and run a port scan against the demo environment iptables is configured to log dropped packets so this will trigger the port scan scenario.

#### SSH bruteforce

Download a bruteforce tool like `Hydra` and run against the demo environment. Environment init will allow passwords authentication for all accounts.

#### SSH impossible travel

The environment init creates a `test` account with a random password (Credentials are dumped to `/root/test_account.txt`). Firstly login to test account from your machine and then login to the same account from another IP address using a VPN or SSH tunnel. This will trigger the impossible travel scenario and the test account will be disabled and the last IP address will be blocked.

Remove the decision against the user and the user will be granted access back (Can be delayed for up to 10 seconds).

#### Captcha remediation

The environment post add captcha remediation to `/etc/crowdsec/profiles.yaml`. This means any HTTP based scenarios will get a captcha remediation. The simplest way to trigger this is download a tool like Gobuster and run a directory brute force against the demo environment.

Beware of running tools like `Nikto` since they can also trigger CVE scenarios and you may just bypass the captcha remediation.

#### Auditd Sus

The environment init script will setup auditd to log all commands run by users created suid > 1000 and logs them to `/var/log/audit/audit.log`. To trigger this scenario use `sudo su test` to transfer from root -> test user account, then you can download `auditd-sus.sh` and run it as the test user.

**Note** Currently we do not deploy a notification plugin so you will have to `cat /var/log/crowdsec.log` to see the triggered scenarios.

### Attacker.sh

This script will install and scaffold a bunch of aliases for you to run against the demo environment. Here is a breakdown of the aliases.

```
sshbruteforce <user>@<ip>
```

Will launch a ssh bruteforce attack against the specified IP and User

```
webscan http[s]://<ip>
```

Will launch a http scanner against the specified IP


```
cvescan http[s]://<ip>
```

Will launch a cve scanner against the specified IP
