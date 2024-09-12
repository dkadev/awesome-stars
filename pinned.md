# Pinned Awesome Stars

> Pinned projects that I use frequently. This list is updated manually. Based on checking and testing the projects from the other lists.

I am always saving interesting projects and tools, this repo auto-deploys and keeps a large list but, I periodically do a cleanup through this method.

Methodology:

1. Star a repo at any time we cross paths.
2. Add it to a Github Star list (first categorizing).
3. Test it someday.
4. Choose:
    - Loved it? 😍 --> add it to the pinned list
    - It's not useful at all --> remove the star
    - Not using it soon but want to keep it --> do nothing

## Contents

### Security
---

- [Penetration Testing](#pentesting)
- [Red Team](#red-team)
- [Blue Team](#blue-team)
- [Threat Intelligence](#threat-intelligence)
- [OSINT](#osint)
- [Forensics](#forensics)
- [Malware Analysis](#malware-analysis)

#### Pentesting

##### Multi-purpose ⭐
- [byt3bl33d3r/CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - A swiss army knife for pentesting networks
- [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) - The Network Execution Tool
- [The-Viper-One/PsMapExec](https://github.com/The-Viper-One/PsMapExec) - A PowerShell tool that takes strong inspiration from CrackMapExec / NetExec

##### Exploits
- [vulnersCom/getsploit](https://github.com/vulnersCom/getsploit) - Command line utility for searching and downloading exploits
- [trickest/cve](https://github.com/trickest/cve) - Gather and update all available and newest CVEs with their PoC.
- [trickest/find-gh-poc](https://github.com/trickest/find-gh-poc) - Find CVE PoCs on GitHub

##### Shells
- [nodauf/Girsh](https://github.com/nodauf/Girsh) - Automatically spawn a reverse shell fully interactive for Linux or Windows victim
- [SkyperTHC/curlshell](https://github.com/SkyperTHC/curlshell) - reverse shell using curl
- [skelsec/evilrdp](https://github.com/skelsec/evilrdp) - 

##### Bruteforcing
- [evilsocket/legba](https://github.com/evilsocket/legba) - A multiprotocol credentials bruteforcer / password sprayer and enumerator.  🥷

##### Bypass
- [Sn1r/Forbidden-Buster](https://github.com/Sn1r/Forbidden-Buster) - A tool designed to automate various techniques in order to bypass HTTP 401 and 403 response codes and gain access to unauthorized areas in the system. This code is made for security enthusiasts and pr
- [iamj0ker/bypass-403](https://github.com/iamj0ker/bypass-403) - A simple script just made for self use for bypassing 403
- [trap-bytes/403jump](https://github.com/trap-bytes/403jump) - HTTP 403 bypass tool
- [devploit/nomore403](https://github.com/devploit/nomore403) - Tool to bypass 403/40X response codes.
- [sAjibuu/Upload_Bypass](https://github.com/sAjibuu/Upload_Bypass) - A simple tool for bypassing file upload restrictions.
- [waf-bypass-maker/waf-community-bypasses](https://github.com/waf-bypass-maker/waf-community-bypasses) - 

##### Port scanners
- [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) - A fast port scanner written in go with a focus on reliability and simplicity. Designed to be used in combination with other tools for attack surface discovery in bug bounties and pentests
- [jtesta/ssh-audit](https://github.com/jtesta/ssh-audit) - SSH server & client security auditing (banner, key exchange, encryption, mac, compression, compatibility, security, etc)
- [MattKeeley/Spoofy](https://github.com/MattKeeley/Spoofy) - Spoofy is a program that checks if a list of domains can be spoofed based on SPF and DMARC records.

#### SSL and HTTP headers
- [rbsec/sslscan](https://github.com/rbsec/sslscan) - sslscan tests SSL/TLS enabled services to discover supported cipher suites
- [santoru/shcheck](https://github.com/santoru/shcheck) - A basic tool to check security headers of a website
- [rfc-st/humble](https://github.com/rfc-st/humble) - A humble, and 𝗳𝗮𝘀𝘁, security-oriented HTTP headers analyzer.

##### Web scanners
- [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) - Fast and customizable vulnerability scanner based on simple YAML based DSL.
- [gotr00t0day/Gsec](https://github.com/gotr00t0day/Gsec) - Web Security Scanner
- [AiGptCode/Ai-Security-URL](https://github.com/AiGptCode/Ai-Security-URL) - functions to exploit common web application vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF), and Path Traversal.
- [oppsec/juumla](https://github.com/oppsec/juumla) - 🦁 Juumla is a python tool created to identify Joomla version, scan for vulnerabilities and sensitive files

##### Web Fuzzing
- [pikpikcu/nodesub](https://github.com/pikpikcu/nodesub) - Nodesub is a command-line tool for finding subdomains in bug bounty programs
- [0xKayala/NucleiFuzzer](https://github.com/0xKayala/NucleiFuzzer) - NucleiFuzzer is a Powerful Automation tool for detecting XSS, SQLi, SSRF, Open-Redirect, etc.. Vulnerabilities in Web Applications
- [mschwager/route-detect](https://github.com/mschwager/route-detect) - Find authentication (authn) and authorization (authz) security bugs in web application routes.
- [r0oth3x49/ghauri](https://github.com/r0oth3x49/ghauri) - An advanced cross-platform tool that automates the process of detecting and exploiting SQL injection security flaws
- [YasserREED/NoBlindi](https://github.com/YasserREED/NoBlindi) - NoBlindi is a command-line tool for exploiting blind NoSQL injection vulnerabilities to recover passwords in web applications.
- [HalilDeniz/PathFinder](https://github.com/HalilDeniz/PathFinder) - Web Path Finder
- [codingo/NoSQLMap](https://github.com/codingo/NoSQLMap) - Automated NoSQL database enumeration and web application exploitation tool.
- [dub-flow/sessionprobe](https://github.com/dub-flow/sessionprobe) - SessionProbe is a multi-threaded tool designed for penetration testing and bug bounty hunting. It evaluates user privileges in web applications by taking a session token and checking access across a l

##### Wordlists
- [t3l3machus/psudohash](https://github.com/t3l3machus/psudohash) - Generates millions of keyword-based password mutations in seconds.
- [sc0tfree/mentalist](https://github.com/sc0tfree/mentalist) - Mentalist is a graphical tool for custom wordlist generation. It utilizes common human paradigms for constructing passwords and can output the full wordlist as well as rules compatible with Hashcat an
- [Mebus/cupp](https://github.com/Mebus/cupp) - Common User Passwords Profiler (CUPP)
- [p0dalirius/LDAPWordlistHarvester](https://github.com/p0dalirius/LDAPWordlistHarvester) - A tool to generate a wordlist from the information present in LDAP, in order to crack passwords of domain accounts.
- [Anof-cyber/ParaForge](https://github.com/Anof-cyber/ParaForge) - A BurpSuite extension to create a custom word-list of endpoint and parameters for enumeration and fuzzing
- [eversinc33/CredGuess](https://github.com/eversinc33/CredGuess) - Generate password spraying lists based on the pwdLastSet-attribute of users.
- [t3l3machus/BabelStrike](https://github.com/t3l3machus/BabelStrike) - The purpose of this tool is: 1. to transliterate and generate possible usernames out of a full names list that may include names written in multiple (non-English) languages, common problem occurring f

##### Active Directory
- [ropnop/kerbrute](https://github.com/ropnop/kerbrute) - A tool to perform Kerberos pre-auth bruteforcing
- [61106960/adPEAS](https://github.com/61106960/adPEAS) - Powershell tool to automate Active Directory enumeration.
- [dievus/msLDAPDump](https://github.com/dievus/msLDAPDump) - LDAP enumeration tool implemented in Python3
- [Mazars-Tech/AD_Miner](https://github.com/Mazars-Tech/AD_Miner) - AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
- [Orange-Cyberdefense/LinikatzV2](https://github.com/Orange-Cyberdefense/LinikatzV2) - linikatz is a tool to attack AD on UNIX
- [dirkjanm/BloodHound.py](https://github.com/dirkjanm/BloodHound.py) - A Python based ingestor for BloodHound
- [NH-RED-TEAM/RustHound](https://github.com/NH-RED-TEAM/RustHound) - Active Directory data collector for BloodHound written in Rust. 🦀

##### Kubernetes
- [Rolix44/Kubestroyer](https://github.com/Rolix44/Kubestroyer) - Kubernetes  exploitation tool
- [DataDog/KubeHound](https://github.com/DataDog/KubeHound) - Tool for building Kubernetes attack paths

##### Secrets

##### Tunneling
- [jpillora/chisel](https://github.com/jpillora/chisel) - A fast TCP/UDP tunnel over HTTP
- [rootcathacking/catspin](https://github.com/rootcathacking/catspin) - Catspin rotates the IP address of HTTP requests making IP based blocks or slowdown measures ineffective. It is based on AWS API Gateway and deployed via AWS Cloudformation.

##### Vuln scanners
- [CERT-Polska/Artemis](https://github.com/CERT-Polska/Artemis) - A modular vulnerability scanner with automatic report generation capabilities.
- [capture0x/LFI-FINDER](https://github.com/capture0x/LFI-FINDER) - LFI-FINDER is an open-source tool available on GitHub that focuses on detecting Local File Inclusion (LFI) vulnerabilities
- [casterbyte/Above](https://github.com/casterbyte/Above) - Invisible network protocol sniffer

##### Wi-Fi
- [jawaharputti/EHTools](https://github.com/jawaharputti/EHTools) - Wi-Fi tools keep getting more and more accessible to beginners, and the Ehtools Framework  is a framework of serious penetration tools that can be explored easily from within it. This  powerful and si

##### Cloud
- [cisagov/ScubaGear](https://github.com/cisagov/ScubaGear) - Automation to assess the state of your M365 tenant against CISA's baselines
- [nccgroup/PMapper](https://github.com/nccgroup/PMapper) - A tool for quickly evaluating IAM permissions in AWS.
- [hotnops/apeman](https://github.com/hotnops/apeman) - AWS Attack Path Management Tool - Walking on the Moon
- [salesforce/cloudsplaining](https://github.com/salesforce/cloudsplaining) - Cloudsplaining is an AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized report.
- [duo-labs/parliament](https://github.com/duo-labs/parliament) - AWS IAM linting library
- [welldone-cloud/aws-lint-iam-policies](https://github.com/welldone-cloud/aws-lint-iam-policies)
- [padok-team/yatas](https://github.com/padok-team/yatas) - :owl::mag_right: A simple tool to audit your AWS/GCP infrastructure for misconfiguration or potential security issues with plugins integration
- [iknowjason/edge](https://github.com/iknowjason/edge) - Recon tool for cloud provider attribution.  Supports AWS, Azure, Google, Cloudflare, and Digital Ocean.
- [optiv/KnockKnock](https://github.com/optiv/KnockKnock) - Enumerate valid users within Microsoft Teams and OneDrive with clean output.
- [RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu) - The AWS exploitation framework, designed for testing the security of Amazon Web Services environments.
- [tenable/EscalateGPT](https://github.com/tenable/EscalateGPT) - An AI-powered tool for discovering privilege escalation opportunities in AWS IAM configurations.
- [spyboy-productions/CloakQuest3r](https://github.com/spyboy-productions/CloakQuest3r) - Uncover the true IP address of websites safeguarded by Cloudflare & Others

##### Mobile
- [amrudesh1/morf](https://github.com/amrudesh1/morf) - Mobile Reconnaissance Framework is a powerful, lightweight and platform-independent offensive mobile security tool designed to help hackers and developers identify and address sensitive information wi

##### Other
- [mandiant/commando-vm](https://github.com/mandiant/commando-vm) - Complete Mandiant Offensive VM (Commando VM), a fully customizable Windows-based pentesting virtual machine distribution. commandovm@mandiant.com

#### Red Team

#### Blue Team

#### Threat Intelligence

#### OSINT

#### Forensics
- [libimobiledevice/ideviceinstaller](https://github.com/libimobiledevice/ideviceinstaller) - Manage apps of iOS devices
- [mvt-project/mvt](https://github.com/mvt-project/mvt) - MVT (Mobile Verification Toolkit) helps with conducting forensics of mobile devices in order to find signs of a potential compromise.
 
#### Malware Analysis
- [sandboxie-plus/Sandboxie](https://github.com/sandboxie-plus/Sandboxie) - Sandboxie Plus & Classic

### AI
---

### Development
---

#### Frontend

#### Backend

#### DevOps
- [will-moss/isaiah](https://github.com/will-moss/isaiah) - Self-hostable clone of lazydocker for the web. Manage your Docker fleet with ease

