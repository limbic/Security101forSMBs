# Security 101 for SMBs
![Alt text](media/security101titleslide.png?raw=true "Title slide")
- [Introduction](#introduction)
	- [Presentation deck (PDF) and Mindmap](#deck-and-mindmap)
- [Go Do Checklist](#go-do-checklist)
    + [Create an Inventory of all your IT assets](#create-an-inventory-of-all-your-it-assets)
    + [Clean-up and simplify (Reduce Attack Surface)](#clean-up-and-simplify)
    + [Update and Harden (Vulnerability management)](#update-and-harden)
    + [Identity and Access Management](#identity-and-access-management)
    + [Encrypt your data](#encrypt-your-data)
    + [Anti-malware](#anti-malware)
    + [Email and Reputation](#email-and-reputation)
    + [Detection](#detection)
    + [Backup and Recovery](#backup-and-recovery)




## Introduction 

This is a companion resource for the "Microsoft Presents - Security 101 for SMBs" workshop dlivered at Directions EMEA 2022 in Hamburg, Germany. 

This is still a work in progress. Additional sections will be added soon ("SDL: Security for Software Creators", "Advanced Security Topics", "Personal Security" plus additional sources and resources.)

### Deck and Mindmap

- Deck:
- [MindMap](/media/Security101forSMBs.html)


## Go Do Checklist 


### Create an Inventory of all your IT assets 
- [ ] **Create an inventory of all asset**- Start simple (Excel, Google Sheets) and evolve to managed solutions
	- Assets to Include: 
		- **Devices**: Laptops, IoT, servers, routers, mobile devices
		- **Software & Services**: Applications, Open-Source Components, Frameworks (e.g., .NET)
		- **Accounts** (incl. Cloud): Subscriptions, users, groups, service principals
		- **Digital asserts**: IPs, Domains, certificates, open ports
		- **Data Stores**: Cloud storage, databases, backup locations

### Clean-up and simplify 

Reduce Attack Surface

- [ ] Remove & safely dispose of unused/unmanaged/unauthorized **hardware**
  - Collect and safely dispose of or recycle old devices, hard drives, laptops
	- Enforce via Intune or other Conditional Access
- [ ] Remove and restrict **unauthorized software**. Restrict what software , apps and browser extensions can be run on your devices, computers and servers
  - Enforce via policies or endpoint management 
- [ ] Remove **unauthorized users and accounts**
- [ ] Remove and restrict **OAuth app permissions** (Google, M365)
- [ ] **Operationalize inspections and regular clean-ups**
	- Have a reminder to regularly update and clean-up the inventory
- [ ] **Vet vendors, services and suppliers** to reduce risk of supply chain attacks 

### Update and Harden 

Practice vulnerability management. 

- [ ] Configure auto-update where possible 
	- On Windows use [Microsoft’s winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/)) with task scheduler
		- [Ninite Updater](https://ninite.com/updater/)) is GUI alternative
	- On Mac use [MacUpdater](https://www.corecode.io/macupdater/)) (app), [Homebrew](https://brew.sh/)) (package manager) or similar 
	- On Linux search web for “unattended updates linux"
- [ ] Manually update everything else monthly
	-  Create an operations calendar of maintenance and update tasks
- [ ] Review and configure Baseline Security guidance for your Operating Systems (Windows, Mac, Linux, iOS and Android), Devices, Software and Services
	- Example: [Security baselines for Azure](https://learn.microsoft.com/en-us/security/benchmark/azure/security-baselines-overview)
- [ ] Consider using “Hardened” devices and services for privileged access and admin (e.g. [Google’s Advanced Protection Program](https://landing.google.com/advancedprotection/), [iOS Lockdown mode](https://support.apple.com/en-ie/HT212650), [M365’s Advanced Security](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/tenant-wide-setup-for-increased-security?view=o365-worldwide))
- [ ] Document your  baseline security configurations in a Standard Operating Procedure (SOP)
- [ ] Enable a firewall (or Network Security Group) your routers and computers
- [ ] Create a Mobile security baseline. Example policies and controls:
	- Require proper password , no 4-digit pins
	- Harden (e.g., lock screen access to Airplane mode disabled)
	- Create a device theft SOP (e.g. procedures for remote wipe, reporting to law enforcement,  enabling lost mode etc.)
	- Use mobile data (avoid public Wi-Fi) 
	- Disallow downloading of sketchy apps (by policy and/or endpoint management)
- [ ] Harden your Router and Wi-Fi
	- Use WPA2 or WPA
	- No WEP, no Pin
	- Disable UPnP 
	- Change default router password
	- Update router firmware
	- Set up keyword monitoring for vulnerability reports (e.g. “Netgear hacked”, “Netgear vulnerability”)

### Identity and Access Management

Actively practice secrets management 

- [ ] Use an Identity Provider  (Microsoft Entera, Google, Apple)
- [ ] Use Passwordless where possible (Passkey, Microsoft passwordless)
- [ ] Store all other secrets in a dedicated secure store 
	- Azure Key Vault, Password manger
- [ ] Use a Password Manager for passwords
	- [1Password](https://1password.com/)), [Bitwarden](https://bitwarden.com/)), [LastPass](https://www.lastpass.com/)), [KeePass Password Safe](https://keepass.info/)) are all good
- [ ] Periodically Review and rotate all secrets
	- Password managers can help do this painlessly 
- [ ] Create an Emergency Secret Rotation SOP
	- If you get compromised, you will want to know what secrets to change/rotate and in what order (of importance)
- [ ] Use Multifactor Authentication for everything 
	- https://twofactorauth.org
	- The best multi-factor options (in order)
	- Physical FIDO token (e.g. YubiKey, Passkey)
	- Authenticator Apps (e.g. Microsoft Authenticator, Google Authenticator, Authy)
	- Phone call / SMS (**avoid** -  vulnerable to [SIM Swapping](https://en.wikipedia.org/wiki/SIM_swap_scam)))
- [ ] Set up breach monitoring 
	- [https://www.haveibeenpwnd.com](https://www.haveibeenpwnd.com/)
	- Password Managers and several browsers (Edge, Chrome, Firefox) offer this too

### Encrypt your data

- [ ] Ensure everything is encrypted In-transit
	- Only use services using TLS 1.2+ or better
	- Use [Let's Encrypt](https://letsencrypt.org/)) to enable HTTPs for your domain 
	- Use a good VPN on any untrusted network (public Wi-Fi)
		- Create your own with OpenVPN and free ter cloud accounts
		- Otherwise pay for a decent provider (e.g. [ProtonVPN](https://protonvpn.com/)), [Freedome](https://www.f-secure.com/en/home/products/freedome), [Private Internet Access](https://www.privateinternetaccess.com/)))
- [ ] Ensure everything is encrypted At rest
	- Bitlocker/Device encryption (Windows, iOS, iPadOS, Android)
	- Filevault (OSX)
	-  Full disk encryption (_FDE_) (Linux)
- [ ] Explore Bring Your Own Key (BYOK) for services that support it

### Anti-malware

Prevent malicious code running on your systems

- [ ] Ensure every device is running Anti-malware
	- Defender for Endpoint has you covered
	- If infected, delete (VM) or wipe (device) 
- [ ] Enable and use [SmartScreen](https://support.microsoft.com/en-us/microsoft-edge/how-can-smartscreen-help-protect-me-in-microsoft-edge-1c9a874a-6826-be5e-45b1-67fa445a74c8) (or similar)
- [ ] Use Secure DNS
	- 1.1.1.1 for Families (CloudFlare)
		- 1.1.1.2 (No Malware)
		- 1.1.1.3 (No Malware or Adult Content)
		- NSEC (privacy)
- [ ] Use Ad blocking & Tracking Prevention
	- Use a good browser ad blocker (e.g. uBlock Origin)
	- Set up [Pi Hole ](https://pi-hole.net/)(Open-Source network ad blocker) on your home and office networks 
- [ ] Consider paying for network threat detection (SMB version)
	- Router threat detection services  (e.g., Unifi threat management module, [Netgear Armor](https://www.netgear.com/ie/home/services/armor/))
	- New generation of plug-and-play threat detection devices (e.g., [GuardDog.ai](https://guarddog.ai/))

### Email and Reputation

Prevent reputation damage from slander and being spoofed

- [ ] Warn staff about Chat based Phishing and MFA spamming
- [ ] Oversharing on social media can be fatal to your business 
- [ ] Use web monitoring to detect cybersquatting, trademark violations, excessive digital footprint (oversharing online) and indicators of compromise
	- Social media monitoring 
	- Google/Bing custom alerts 
	- Dark Web Monitoring (e.g. https://www.immuniweb.com/darkweb/, https://haveibeenpwned.com )
- [ ] Set up Domain-based Message Authentication, Reporting, and Conformance ([DMARC](https://dmarc.org/)) , Sender Policy Framework (SPF) and DomainKeys Identified Mail (DKIM) to authenticate mail senders

### Detection

Use an attacker’s lens to examine your SMB

- [ ] Investigate Microsoft's phenomenal security portfolio 
	 - [How Microsoft Security partners are helping customers do more with less - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/19/how-microsoft-security-partners-are-helping-customers-do-more-with-less/)
- [ ] Examine your SMB with Attacker’s lens (the toolset used by hackers and Red teams)
	- Scan your websites, IP addresses and environments (e.g., [Immuniweb Websec](https://www.immuniweb.com/websec/), [Password Auditor](https://specopssoft.com/product/specops-password-auditor/), [BloodHound](https://github.com/BloodHoundAD/BloodHound), [Shodan.io](https://www.shodan.io/), [Pentest Tools](https://pentest-tools.com/) etc.,)
- [ ] Pay for good (competent and thorough) Penetration Testing once a year 

### Backup and Recovery

It is not only bad guys that can destroy your business

- [ ] Ensure you have functioning and ransomware resistant backups! 
	- One local (e.g. Time Machine), 
	- One in the cloud (e.g. OneDrive),
	- One copy offline (disconnected disk or tape)
- [ ] Encrypt your backups (but take care of the encryption key!) 
- [ ] Test restoring from those backups in realistic Incident Response drills
	- 60% SMBs do not survive ransomware attacks
	- Even with good, complete, recent backups – recovery is hard
