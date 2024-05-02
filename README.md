# sans-index-generator
**Generate Indexes from SANS PDFs**

> NOTE: May not work with all SANS PDFs due to different structures. Modify the `fix_text` and `extract_pdf_text` methods in `extractpdfs.py` to match the structure of the PDFs you are working with if errors occur.

## Setup
Run the following command to clone the repository and run the setup script.
```bash
git clone https://github.com/LucasFaudman/sans-index-generator && cd sans-index-generator && chmod +x setup.sh && ./setup.sh
```

## Usage
```bash
usage: extractpdfs.py [-h] [-P PASSWORD] [-O OUT] [--maxwidth MAXWIDTH]
                      [--only-page-order] [--only-alpha]
                      [--keep-roadmap | --no-keep-roadmap]
                      [--keep-toc | --no-keep-toc]
                      [--keep-continuation | --no-keep-continuation]
                      [--keep-summary | --no-keep-summary]
                      [--keep-labs | --no-keep-labs] [--load-index LOAD_INDEX]
                      [--save-index SAVE_INDEX]
                      [FILENAMES ...]

Extracts indexes from SANS PDF files.

positional arguments:
  FILENAMES             the PDF files to unlock and extract indexes from

optional arguments:
  -h, --help            show this help message and exit
  -P PASSWORD, --password PASSWORD
                        the password to unlock the PDF files
  -O OUT, --out OUT     Output file
  --maxwidth MAXWIDTH   Maximum width of output
  --only-page-order     Print index only in page order
  --only-alpha          Print index only in alphabetical order
  --keep-roadmap, --no-keep-roadmap
                        Keep roadmap
  --keep-toc, --no-keep-toc
                        Keep table of contents
  --keep-continuation, --no-keep-continuation
                        Keep continuation
  --keep-summary, --no-keep-summary
                        Keep summary
  --keep-labs, --no-keep-labs
                        Keep labs
  --load-index LOAD_INDEX
                        Load index from file
  --save-index SAVE_INDEX
                        Save index to file
```

## Example Output
```
560/SEC560-Book1.pdf:

11: Terms Vulnerability, Exploit
12: Terms Threat Risk
13: Terms Pen Test, Red Team, Purple Team, Audit
14: Terms Vulnerability Assessment, Security Audit
15: Terms Penetration Testing Goals
16: Terms Types of Penetration Tests
17: Terms Attack Phases
19: Pre-Engagement Penetration Testing Process Phases
20: Pre-Engagement Documented Permission
21: Pre-Engagement Steps
22: Pre-Engagement Goals
23: Pre-Engagement Scope
24: Pre-Engagement Rules of Engagement
25: Pre-Engagement Announced vs. Unannounced Tests
26: Pre-Engagement Zero-Knowledge vs. Full-Knowledge Testing
27: Pre-Engagement Viewing Data on Compromised Systems
28: Pre-Engagement Kickoff Call
33: Building Infrastructure
34: Building Infrastructure Building a Lab
35: Building Infrastructure Systems Used for Internal Testing
36: Building Infrastructure Dedicated Test Systems
37: Building Infrastructure Sources for Free Tools and Exploits
38: Building Infrastructure MITRE ATT&CK
39: Building Infrastructure Tools for Penetration Testing Teams
42: Linux vs.Windows
43: Linux Fun Ease-of-Use Shell Tips
44: Linux Users: Root and Non-root
45: Linux Who Am I?
46: Linux File System Structure
47: Linux Where Am I?
48: Linux Navigating the Filesystem
49: Linux Listing Files
50: Linux Permissions
51: Linux Escalating with SETUID
52: Linux Escalation
53: Linux Commands for Pen Testers
54: Linux Software for Testing: Prepackaged Testing Suites
55: Command Prompts
61: Recon Motivation
62: Recon Traffic
63: Recon Targets
64: Recon Social Engineering and Ethics
67: Recon Org Information on the Organization
68: Recon Org Press Releases and Annual Reports
69: Recon Org Gather Competitive Intelligence
71: Recon Infrastructure
72: Recon Infra Hostname Information
73: Recon Infra DNSRecon
74: Recon Infra DNSRecon Usage
75: Recon Infra DNSDumpster
76: Recon Infra DNSDumpster Usage (1)
77: Recon Infra DNSDumpster Usage (2)
78: Recon Infra WHOIS + Regional Internet Registries
79: Recon Infra Certificate Transparency Logs
80: Recon Infra Shodan
83: Recon User Hunter.io
84: Recon User phonebook.cz lists emails, URLs for a domain
85: Recon User Public Breach Data of Credentials
86: Recon User Look for Open Job Requisitions
87: Recon User LinkedIn can provide a lot of information on employees
88: Recon User GatherContacts
89: Recon User GatherContacts Results
93: Scanning Goals of Scanning Phase
94: Scanning Scan Types
95: Scanning Tip: Dealing with Very Large Scans
96: Scanning Handling Large Scans by Limiting Scope
98: Scanning Port Protocol Layers and TCP vs. UDP
99: Scanning Port TCP Header
100: Scanning Port TCP Flags
101: Scanning Port TCP Three-Way Handshake
102: Scanning Port Handshake Happens Regardless of Higher-Level Protocol
103: Scanning Port TCP Behavior (1)
104: Scanning Port TCP Behavior (2):
105: Scanning Port UDP Header
106: Scanning Port UDP Behavior (1)
107: Scanning Port UDP Behavior (2)
109: Nmap Port Scanner
110: Nmap's Timing Options
111: Nmap Input and Output Options
112: Nmap and Address Probing
113: Nmap Network Probe/Sweeping Options
114: Nmap Optimizing Host Detection
115: Nmap Port Scanning (After Host Detection)
116: Nmap TCP Port Scan Types: Connect Scan
117: Nmap UDP Scans
121: Nmap Limitations and Host Groups
122: Masscan vs Nmap Faster Scanning
123: Masscan
124: Masscan Output
125: Masscan Extracting Live Hosts and Open Ports
129: Nmap Active OS Fingerprinting
130: Nmap Version Scanning
131: Nmap Version Scanning Functionality
133: Netcat for the Pen Tester
134: Netcat Command Flags
135: Netcat Client Grabbing Service Info
136: Netcat Automating Service String Information
137: Netcat uses a Lowercase L
138: Netcat Moving Files
140: EyeWitness
141: EyeWitness Specifying Targets
142: EyeWitness Report Content
143: EyeWitness What to Look For
145: Scanning Vulns Methods for Discovering Vulnerabilities (1)
146: Scanning Vulns Methods for Discovering Vulnerabilities (2)
147: Scanning Vulns Scanner Goals
148: Scanning Vulns Scan Types
149: Scanning Vulns Safe Checks and Dangerous Plugins
150: Scanning Vulns Scan Results
151: Nmap Version Scan as Vulnerability Scanner?
153: Nmap Scripting Engine
154: Nmap Scripting Engine Scripts
155: Nmap NSE Script Categories
156: Nmap Some Example NSE Scripts


560/SEC560-Book2.pdf:

5 : Initial Access Background
6 : Initial Access Where Does Access Come From
8 : Password Guessing The Importance of Passwords
9 : Password Guessing Credential Stuffing
10: Password Guessing Credential Databases
11: Password Guessing Types of Online Password Attacks
12: Password Guessing with a Custom Dictionary
13: Password Guessing Trimming Word Lists with Hydra's pw-inspector
14: Password Guessing Guessing Usernames
15: Password Guessing Account Lockout
16: Password Guessing Account Lockout on Windows
17: Password Guessing Active Directory Lockout Scenario
18: Password Guessing Suggested Spray Technique
19: Password Guessing Tools
20: Password Guessing Hydra
21: Password Guessing Hydra Examples
22: Password Guessing Hydra with the Domain
26: Exploitation What Is Exploitation?
27: Exploitation Why use Exploitation?
28: Exploitation Risks of Exploitation
30: Exploitation Categories of Exploits
31: Exploitation Server-Side Exploits
32: Exploitation Client-Side Exploits
33: Exploitation Client-Side Commonly Vulnerable Software
34: Exploitation Mounting a Client-Side Exploitation Campaign
35: Exploitation Client-Side Exploits and Guardrails
36: Exploitation Using Payloads on Target Systems
37: Exploitation Use Appropriate, Representative Client Machines
38: Exploitation Local PrivEsc Exploits
39: Exploitation Local PrivEsc Attack Categories and Suites
41: Metasploit Exploitation Framework
42: Metasploit Design
43: Metasploit User Interfaces
44: Metasploit Modules (exploits, payloads, auxiliary, post)
45: Metasploit Exploit Arsenal
46: Metasploit Windows Exploits
47: Metasploit Exploit Rankings
48: Metasploit Modules: Payloads
49: Metasploit Payloads: Windows Singles
50: Metasploit Payloads: Windows Stagers
51: Metasploit Payloads: Windows Stages
52: Meterpreter Overview
53: Meterpreter Functionality: Some Base Commands
54: Meterpreter Functionality: Process Commands
55: Meterpreter Functionality: File System Commands
56: Meterpreter Stdapi Capabilities: Networking Commands
57: Meterpreter Functionality:Target Machine Console
58: Meterpreter Functionality: Keystroke Logger
59: Meterpreter Functionality: Pivoting Using Route
60: Meterpreter Functionality: Additional Modules
65: Assumed Breach
66: Assumed Breach What About Initial Access?
67: Assumed Breach Access via 0-Day
68: Assumed Breach Test Assumptions
69: Assumed Breach Analyzing Modern Attacks
70: Assumed Breach Post-Exploitation
72: C2 What is a C2 Framework
73: C2 The C2 Matrix
74: C2 Matrix Google Sheet
76: C2 Sliver C2 Framewor Overview
77: C2 Sliver Features
78: C2 Sliver Features Supporting Offensive Operations
79: C2 Sliver Payload File Format Options
80: C2 Sliver Payload Options
81: C2 Sliver Implant Commands
82: C2 Sliver Multiplayer
83: C2 Sliver Generating Payloads
87: C2 Empire Overview
88: C2 Empire Features
89: C2 Empire Features Supporting Offensive Operations
90: C2 Empire Modules
91: C2 Empire Module Categories (1)
92: C2 Empire Module Categories (2)
96: Payloads Overview
97: Payloads Common Payload Types
98: Payloads Using Macros
99: Payloads VBA
100: Payloads DDE
101: Payloads ISO
102: Payloads Zip File
103: Payloads LNK Files
107: Post-Exploitation Activities
108: Post Exploitation Tactics
109: Post-Exploitation File Transfer (HTTP, SCP, FTP, TFTP)
110: Post-Exploitation File Transfer (SMB, NFS mounts, Netcat)
111: Post-Exploitation File Transfer (Meterpreter)
112: Post-Exploitation File Transfer (Copy/Paste to Move Files)
114: Situational Awareness Overview
115: Situational Awareness File Pilfering
116: Situational Awareness Network Pilfering
118: Situational Awareness Linux Accounts
119: Situational Awareness Linux Groups
120: Situational Awareness Linux Interesting Files (1)
121: Situational Awareness Linux Interesting Files (2)
122: Situational Awareness Linux Local File Pilfering
124: Situational Awareness Windows Environment Variables
125: Situational Awareness Windows Searching the File System
126: Situational Awareness Windows Managing Accounts and Groups
127: Situational Awareness Windows Domain User
128: Situational Awareness Windows Local Groups
129: Situational Awareness Windows Domain Groups
130: Situational Awareness Windows Deleting Users and Accounts
131: Situational Awareness Windows Determining Firewall Settings
132: Situational Awareness Windows Displaying and Searching Files
133: Situational Awareness Windows Interacting with the Registry
134: Situational Awareness Windows PowerView
135: Situational Awareness Windows AD Explorer
137: Situational Awareness Windows Seatbelt GhostPack Overview
138: Situational Awareness Windows Seatbelt Executing Checks
139: Situational Awareness Windows Seatbelt Command Groups


560/SEC560-Book3.pdf:

5 : PrivEsc Why PrivEsc?
7 : PrivEsc Linux Why Linux?
8 : PrivEsc Linux Kernel Exploits
9 : PrivEsc Linux Services Running as Root
10: PrivEsc Linux PrivEsc Linux World Writeable Files
11: PrivEsc Linux SETUID
12: PrivEsc Linux GTFOBins
14: PrivEsc Windows Common Flaws
15: PrivEsc Windows Unattended Install Files
16: PrivEsc Windows Unattended Install Files Contents
17: PrivEsc Windows Group Policy Preference (GPP) Files
18: PrivEsc Windows Group Policy Preference (GPP)
19: PrivEsc Windows Unquoted Paths with Spaces (1)
20: PrivEsc Windows Unquoted Paths with Spaces (2)
21: PrivEsc Windows User Account Control (UAC)
22: PrivEsc Windows UAC Levels
23: PrivEsc Windows UAC Bypass Techniques
24: PrivEsc Windows Tools (BeRoot, Watson, PowerUp)
25: PrivEsc Windows PowerUp
26: PrivEsc Windows LOLBAS
30: BloodHound Overview
31: BloodHound How Do We Know Where to Steal Credentials?
32: BloodHound Ingestion via SharpHound
33: BloodHound Queries
34: BloodHound Graph Interface
35: BloodHound Marking Targets (Owned, High Value)
39: Persistence Why Persistence
40: Persistence Windows Registry
41: Persistence Windows Startup Folder
42: Persistence Windows Scheduled Task
43: Persistence Windows Services
44: Persistence Windows WMI Event Consumer
48: Password Cracking vs. Password Guessing
49: Password Cracking Synced Passwords
50: Password Cracking Dictionaries
51: Password Cracking Custom Dictionaries
52: Password Cracking Update Your Dictionary
53: Password Cracking Improving Speed
54: Password Cracking Alts (Sniffing, Keyloggers, Pass-the-Hash)
55: Password Cracking Considerations
56: Password Cracking Reporting
58: Password Reprs Windows SAM Database
59: Password Reprs Windows AD (ntds.dit)
60: Password Reprs Windows LANMAN Hash Algorithm
61: Password Reprs Windows NT Hash Algorithm
62: Password Reprs Windows Challenge/Response on the Network
63: Password Reprs Windows LANMAN Challenge/Response
64: Password Reprs Windows LANMAN and NTLMv1 Challenge/Response
65: Password Reprs Windows NTLMv2 Challenge/Response
66: Password Reprs Windows NTLMv2 Graphically
67: Password Reprs Windows CAC and Smartcards
68: Password Reprs Linux and UNIX Password Representations
69: Password Reprs Linux MD5-Based Password Scheme
71: Password Dumping Linux/UNIX Password Representations
72: Password Dumping Windows Password Representations
73: Password Dumping Hashes with Meterpreter
74: Password Dumping Windows VSS Volume Shadow Copy Service (ntds.dit+
75: Password Dumping Windows VSS Extract of ntds.dit
76: Password Dumping Windows NTDSUtil
77: Password Dumping Windows from mimikatz Kiwi
81: Password Cracking John the Ripper
82: Password Cracking John Config File and Cracking Modes
83: Password Cracking John john.pot File
84: Password Cracking John Interpreting Output
85: Password Cracking John Speed
86: Password Cracking John vs. Hashcat
88: Password Cracking Hashcat Multithreaded and GPU
89: Password Cracking Hashcat Specifying Hash Types
90: Password Cracking Hashcat Potfile, Show, and Restore
91: Password Cracking Hashcat Dictionaries, and Word Mangling Rules
92: Password Cracking Hashcat Masks
93: Password Cracking Hashcat Mask Examples
94: Password Cracking Hashcat Status and Temp Sensor
95: Password Cracking Pipal Password Pattern Analysis
99: Sniff/Relay Kerberos and NTLMv2
100: Sniff/Relay NTLMv2 Attack Strategies
101: Sniff/Relay Windows Challenge/Response
102: Sniff/Relay PCredz Cracking Process
103: Sniff/Relay PCredz Extracting Hashes
104: Sniff/Relay PCredz Getting the Hashes from Log File
106: Sniff/Relay Resonder Overview
107: Sniff/Relay Resonder Obtain NetNTLMv2 Challenge/Response
108: Sniff/Relay Resonder Web Proxy Autodiscovery Protocol
109: Sniff/Relay Resonder Obtain NetNTLMv2 Other Tricks
110: Sniff/Relay Resonder NTLM Offline Brute Force Hashcat
111: Sniff/Relay Resonder NTLM SMB Relaying
112: Sniff/Relay Resonder NTLM SMB Relaying with Responder
113: Sniff/Relay Resonder Defenses


560/SEC560-Book4.pdf:

5 : LatMov Why Lateral Movement?
6 : LatMov Linux (Cred Reuse, SSO, SSH key theft)
8 : LatMov Windows (LOL, RDP, WMI, WinRM, PsExec, ticket/hash reuse)
9 : LatMov Windows Command Line for Penetration Testers
10: LatMov Windows Remote Management (WinRM)
11: LatMov Windows WinRM and PowerShell
12: LatMov Windows Ticket Reuse
13: LatMov Windows SMB Session Setup
14: LatMov Windows SC Controlling Services with SC
15: LatMov Windows SC Starting and Stopping Services
16: LatMov Windows SC Determining Service Names
17: LatMov Windows Run Cmds on Remote Systems Methods
18: LatMov Windows Run Cmds Sysinternals PsExec.exe (1)
19: LatMov Windows Run Cmds Sysinternals PsExec.exe (2)
20: LatMov Windows Run Cmds Metasploit PsExec Module
21: LatMov Windows Run Cmds schtasks Scheduling a Job
22: LatMov Windows Run Cmds schtasks Run an Executable
23: LatMov Windows Run Cmds SC Invoke an Executable
24: LatMov Windows Run Cmds SC Make Executable a Service
25: LatMov Windows Run Cmds WMIC Invoke a Program
26: LatMov Windows Run Cmds WMIC Interacting with Processes
32: Impacket Overview
33: Impacket Kerberos (GetUserSPNs, ticketer).py
34: Impacket Extracting Hashes (secretsdump.py)
35: Impacket Remote Execution (ps, smb, at, wmi, dcom)exec.py
36: Impacket Syntax
37: Impacket smbexec.py vs wmiexec.py
41: Pass-the-Hash Technique Overview
42: Pass-the-Hash Advantages
43: Pass-the-Hash NTLMv2 Graphically
44: Pass-the-Hash Microsoft's Mitigations
45: Pass-the-Hash C2 Frameworks
46: Pass-the-Hash Metasploit PsExec Module
47: Password Attacks: When to Use Each Technique (with/out hashes)
52: Evasion AV/EDR Evasion Tactics
53: Evasion AV/EDR Approaches
54: Evasion virustotal.com?
55: Evasion AV/EDR (Static vs Dynamic Evasion)
56: Evasion AMSI (Antimalware Scan Interface)
57: Evasion AMSI Initialization in PowerShell
58: Evasion AMSI - AMSI Initialization
59: Evasion AMSI - Downgrade Attacks
60: Evasion AMSI - String Modification
61: Evasion AV/EDR Static Analysis Evasion
62: Evasion AV/EDR Stripping PowerShell Comments
63: Evasion AV/EDR Call API's to Bypass Hooks (SharpBlock)
64: Evasion AV/EDR Signature-Based Detections
65: Evasion AV/EDR Windows Defender (1)
66: Evasion AV/EDR Windows Defender (2)
67: Evasion AV/EDR Windows Defender (3)
68: Evasion AV/EDR Windows Defender (4)
69: Evasion AV/EDR Tools for Automating Evasion
71: Application Control Overview
72: Application Control Bypass
73: Application Control Bypass MSBuild (1)
74: Application Control Bypass MSBuild (2)
75: Application Control Bypass MSBuild (3)
76: Application Control Bypass MSBuild (4)
77: Application Control Bypass MSBuild (5)
78: Application Control Bypass MSBuild (6)
79: Application Control Bypass MSBuild (7)
80: Application Control Bypass MSBuild (8)
84: LatMov Pivoting Metasploit route Command
85: LatMov Pivoting Metasploit Meterpreter Port Forwarding
86: LatMov Pivoting Metasploit Meterpreter Autoroute
87: LatMov Pivoting SSH Local Port Forwarding
88: LatMov Pivoting SSH Dynamic Port Forwarding
94: Reporting Always Create a Report
95: Reporting Don't Just Regurgitate Vuln Scan Results
96: Reporting Recommended Report Format
97: Reporting 1. Executive Summary (1)
98: Reporting 1. Executive Summary (2)
99: Reporting 2. Introduction
100: Reporting 3. Findings
101: Reporting 3. Findings Screenshot to Illustrate Findings
102: Reporting 3. Findings Screenshot Elements
103: Reporting 3. Findings Screenshot Tools
104: Reporting Redaction and Transparency
105: Reporting Recommendations
107: Reporting Validation and Verification
108: Reporting 4. Methodology
109: Reporting Appendices
110: Reporting Recommended Reading
111: Reporting Sample Reports
112: Reporting 3. Findings Order
113: Reporting Be Consistent!
114: Reporting Styles and Themes
115: Reporting Readability
116: Reporting Clean and Succinct Reporting
117: Reporting Use of Colors
118: Reporting Effective Illustrations


560/SEC560-Book5.pdf:

5 : Kerberos Introduction
6 : Kerberos How It Works
7 : Kerberos Overall Flow
8 : Kerberos Three Long-Term Keys (KDC, Client, Target Service)
9 : Kerberos AS-REQ with pre-authentication
10: Kerberos TGT (Ticket Granting Ticket) and PAC
11: Kerberos ST Requesting a Service Ticket
12: Kerberos Service Principal Name
13: Kerberos ST Using a Service Ticket
14: Kerberos ST Service Ticket
16: Kerberoasting Requesting a Service Ticket (ST) Revisited
17: Kerberoasting Requesting a Ticket
18: Kerberoasting Attack Overview
19: Kerberoasting Setspn.exe
20: Kerberoasting Obtaining Tickets (Tools)
21: Kerberoasting Attack Steps
22: Kerberoasting AES vs. RC4
23: Kerberoasting What Service Accounts are Good Targets?
27: Kerberos Pass-the-Ticket
28: Kerberos Pass-the-Ticket Mimikatz Example
29: Kerberos Overpass-the-Hash
30: Kerberos Golden Ticket Overview
32: DomDom and AD Persistence
33: DomDom Obtaining Access to Back-Up NTDS.dit File
35: DomDom Creating a Domain Admin Account
36: DomDom Mimikatz Skeleton Key
37: DomDom Mimikatz Skeleton Key in Action
38: DomDom DCSync Replicating the Domain Controller
39: DomDom DCSync Replicating the Domain Controller Example
40: DomDom DCShadow Becoming a Domain Controller
41: DomDom DCShadow Becoming a Domain Controller Example
42: AD CS Abusing Active Directory Certificate Services
46: AD CS Overview (1)
47: AD CS Overview (2)
48: AD CS Terms (CA, Enterprise CA, Cert Templates, CSR, EKU, Digital Sig)
49: AD CS Internal CA how it Work?
50: AD CS ESC1 (Misconfigured Certificate Templates)
51: AD CS ESC1 CA Configuration
52: AD CS ESC1 Template Misconfiguration (1)
53: AD CS ESC1 Template Misconfiguration (2)
54: AD CS ESC1 Template Misconfiguration (3)
55: AD CS ESC1 Template Misconfiguration (4)
56: AD CS ESC1 Exploitation Tools (Certify, Certipy, Certi, Rubeus)
57: AD CS ESC1 Exploitation Certify List CAs and Templates
58: AD CS ESC1 Exploitation Certify Finding vulnerable templates (1)
59: AD CS ESC1 Exploitation Certify Finding vulnerable templates (2)
60: AD CS ESC1 Exploitation Certify Requesting a certificate
61: AD CS ESC1 Exploitation Certify Convert to .pfx
62: AD CS ESC1 Exploitation Rubeus Requesting a TGT
63: AD CS ESC1 Exploitation Rubeus PrivEsc using TGT (1)
64: AD CS ESC1 Exploitation Rubeus PrivEsc using TGT (2)
65: AD CS ESC1 Exploitation Certipy Find vulnerable CAs + templates (1)
66: AD CS ESC1 Exploitation Certipy Find vulnerable CAs + templates (2)
67: AD CS ESC1 Exploitation Certipy Find vulnerable CAs + templates (3)
68: AD CS ESC1 Exploitation Certipy Requesting a certificate
69: AD CS ESC1 Exploitation Certipy Recovering NT hash
70: AD CS ESC4 (Vulnerable Certificate Template Access Control)
72: AD CS ESC4 Permission Descriptions
73: AD CS ESC4 Identification Certify (1)
74: AD CS ESC4 Identification Certify (2)
75: AD CS ESC4 Identification Certipy (3)
76: AD CS ESC4 Identification Certipy (4)
77: AD CS ESC4 Exploitation Certipy (5)
78: AD CS ESC4 Exploitation Certipy (6)
79: AD CS ESC4 Exploitation Certipy (7)
80: AD CS ESC4 Exploitation Certipy (8)
81: AD CS ESC4 Exploitation Certipy (9)
82: AD CS ESC8 (NTLM Relay to AD CS HTTP Endpoints)
83: AD CS ESC8 Tools (Ntlmrelayx.py, ADCSPwn)
87: Kerberos Silver Ticket Overview
88: Kerberos Silver Ticket Service Ticket and PAC
89: Kerberos Silver Ticket Generation Impacket ticketer.py
90: Kerberos Silver Ticket Use on Linux and Windows
94: Kerberos Golden Ticket Overview
95: Kerberos Golden Ticket Flow
96: Kerberos Golden Ticket Properties
97: Kerberos Golden Ticket Generation Tools (ticketer.py, mimikatz)
101: DomPrivEsc PowerViewFind-InterestingDomainShareFile
102: DomPrivEsc PowerViewFind-LocalAdminAccess
103: DomPrivEsc Process Memory Dumps
104: DomPrivEsc (AS-REP Roasting)
106: Azure Services Overview (1)
107: Azure Services Overview (2)
108: Azure Management Portals
109: Azure AD vs Azure
111: Azure AD Overview
112: Azure AD Authentication Flow (1)
113: Azure AD Authentication Flow (2)
114: Azure AD Authentication Flow (3)
115: Azure AD Authentication Flow (4)
116: Azure AD (Microsoft Authentication Systems compared)
117: Azure AD Identity Architecture Types
118: Azure AD Syncronization and Federation
120: Azure Recon AADInternals Overview
121: Azure Recon AADInternals Recon
122: Azure Recon Username Enumeration Endpoints
123: Azure Recon Username Enumeration GetCredentialType Endpoint
125: Azure Recon Username Enumeration GetCredentialType Throttling
126: Azure Recon Username Enumeration OAuth Token Endpoint (1)
127: Azure Recon Username Enumeration OAuth Token Endpoint (2)
128: Azure Recon Legacy Authentication and Protocols
129: Azure Recon Modern Authentication
131: Azure Password Attacks Password Spraying in Azure
132: Azure Password Attacks TrevorSpray
134: Azure Password Attacks Spray365
135: Azure Password Attacks Spray365 Usage
136: Azure Password Attacks Azure Smart Lockout
137: Azure Password Attacks Azure Smart Lockout Customization
138: Azure Password Attacks Lockout Bypass Overview
139: Azure Password Attacks Lockout Bypass IP Rotation (1)
140: Azure Password Attacks Lockout Bypass IP Rotation (2)
144: Azure OpenID Connect Flows Overview
145: Azure OpenID Connect Authentication Flows (1)
146: Azure OpenID Connect Authentication Flows (2)
147: Azure OpenID Connect Authentication Flows (3)
148: Azure OpenID Connect Authentication Flows (4)
149: Azure OpenID Connect Authentication Flows (5)
150: Azure OpenID Connect Authentication Flows (6)
151: Azure OpenID Connect Authentication Flows (7)
152: Azure OpenID Connect Authentication Flows (8)
153: Azure OpenID Connect Authentication Flows (9)
154: Azure OpenID Connect Authentication Flows (10)
155: Azure OpenID OAuth Flow Types
157: Azure Infrastructure Components
158: Azure Infrastructure Organization
159: Azure Infrastructure Control Plane and Data Plane
161: Azure CLI Tools
162: Azure CLI Basics
163: Azure VM Operations
164: Azure VM Running Commands
166: Azure Permissions Global Administrator
167: Azure Permissions (Builtin and Custom Roles)
168: Azure Permissions IAM Document
169: Azure Permissions Where are Permissions Applied?
170: Azure Permissions IMDS
171: Azure Permissions Managed Identities
175: Ngrok Overview
176: Ngrok How it Works
177: Ngrok Example Flow
178: Ngrok Visualization of ngrok


AD CS Abusing Active Directory Certificate Services                                                        : 5:42       
AD CS ESC1 (Misconfigured Certificate Templates)                                                           : 5:50       
AD CS ESC1 CA Configuration                                                                                : 5:51       
AD CS ESC1 Exploitation Certify Convert to .pfx                                                            : 5:61       
AD CS ESC1 Exploitation Certify Finding vulnerable templates (1)                                           : 5:58       
AD CS ESC1 Exploitation Certify Finding vulnerable templates (2)                                           : 5:59       
AD CS ESC1 Exploitation Certify List CAs and Templates                                                     : 5:57       
AD CS ESC1 Exploitation Certify Requesting a certificate                                                   : 5:60       
AD CS ESC1 Exploitation Certipy Find vulnerable CAs + templates (1)                                        : 5:65       
AD CS ESC1 Exploitation Certipy Find vulnerable CAs + templates (2)                                        : 5:66       
AD CS ESC1 Exploitation Certipy Find vulnerable CAs + templates (3)                                        : 5:67       
AD CS ESC1 Exploitation Certipy Recovering NT hash                                                         : 5:69       
AD CS ESC1 Exploitation Certipy Requesting a certificate                                                   : 5:68       
AD CS ESC1 Exploitation Rubeus PrivEsc using TGT (1)                                                       : 5:63       
AD CS ESC1 Exploitation Rubeus PrivEsc using TGT (2)                                                       : 5:64       
AD CS ESC1 Exploitation Rubeus Requesting a TGT                                                            : 5:62       
AD CS ESC1 Exploitation Tools (Certify, Certipy, Certi, Rubeus)                                            : 5:56       
AD CS ESC1 Template Misconfiguration (1)                                                                   : 5:52       
AD CS ESC1 Template Misconfiguration (2)                                                                   : 5:53       
AD CS ESC1 Template Misconfiguration (3)                                                                   : 5:54       
AD CS ESC1 Template Misconfiguration (4)                                                                   : 5:55       
AD CS ESC4 (Vulnerable Certificate Template Access Control)                                                : 5:70       
AD CS ESC4 Exploitation Certipy (5)                                                                        : 5:77       
AD CS ESC4 Exploitation Certipy (6)                                                                        : 5:78       
AD CS ESC4 Exploitation Certipy (7)                                                                        : 5:79       
AD CS ESC4 Exploitation Certipy (8)                                                                        : 5:80       
AD CS ESC4 Exploitation Certipy (9)                                                                        : 5:81       
AD CS ESC4 Identification Certify (1)                                                                      : 5:73       
AD CS ESC4 Identification Certify (2)                                                                      : 5:74       
AD CS ESC4 Identification Certipy (3)                                                                      : 5:75       
AD CS ESC4 Identification Certipy (4)                                                                      : 5:76       
AD CS ESC4 Permission Descriptions                                                                         : 5:72       
AD CS ESC8 (NTLM Relay to AD CS HTTP Endpoints)                                                            : 5:82       
AD CS ESC8 Tools (Ntlmrelayx.py, ADCSPwn)                                                                  : 5:83       
AD CS Internal CA how it Work?                                                                             : 5:49       
AD CS Overview (1)                                                                                         : 5:46       
AD CS Overview (2)                                                                                         : 5:47       
AD CS Terms (CA, Enterprise CA, Cert Templates, CSR, EKU, Digital Sig)                                     : 5:48       
Application Control Bypass                                                                                 : 4:72       
Application Control Bypass MSBuild (1)                                                                     : 4:73       
Application Control Bypass MSBuild (2)                                                                     : 4:74       
Application Control Bypass MSBuild (3)                                                                     : 4:75       
Application Control Bypass MSBuild (4)                                                                     : 4:76       
Application Control Bypass MSBuild (5)                                                                     : 4:77       
Application Control Bypass MSBuild (6)                                                                     : 4:78       
Application Control Bypass MSBuild (7)                                                                     : 4:79       
Application Control Bypass MSBuild (8)                                                                     : 4:80       
Application Control Overview                                                                               : 4:71       
Assumed Breach                                                                                             : 2:65       
Assumed Breach Access via 0-Day                                                                            : 2:67       
Assumed Breach Analyzing Modern Attacks                                                                    : 2:69       
Assumed Breach Post-Exploitation                                                                           : 2:70       
Assumed Breach Test Assumptions                                                                            : 2:68       
Assumed Breach What About Initial Access?                                                                  : 2:66       
Azure AD (Microsoft Authentication Systems compared)                                                       : 5:116      
Azure AD Authentication Flow (1)                                                                           : 5:112      
Azure AD Authentication Flow (2)                                                                           : 5:113      
Azure AD Authentication Flow (3)                                                                           : 5:114      
Azure AD Authentication Flow (4)                                                                           : 5:115      
Azure AD Identity Architecture Types                                                                       : 5:117      
Azure AD Overview                                                                                          : 5:111      
Azure AD Syncronization and Federation                                                                     : 5:118      
Azure AD vs Azure                                                                                          : 5:109      
Azure CLI Basics                                                                                           : 5:162      
Azure CLI Tools                                                                                            : 5:161      
Azure Infrastructure Components                                                                            : 5:157      
Azure Infrastructure Control Plane and Data Plane                                                          : 5:159      
Azure Infrastructure Organization                                                                          : 5:158      
Azure Management Portals                                                                                   : 5:108      
Azure OpenID Connect Authentication Flows (1)                                                              : 5:145      
Azure OpenID Connect Authentication Flows (10)                                                             : 5:154      
Azure OpenID Connect Authentication Flows (2)                                                              : 5:146      
Azure OpenID Connect Authentication Flows (3)                                                              : 5:147      
Azure OpenID Connect Authentication Flows (4)                                                              : 5:148      
Azure OpenID Connect Authentication Flows (5)                                                              : 5:149      
Azure OpenID Connect Authentication Flows (6)                                                              : 5:150      
Azure OpenID Connect Authentication Flows (7)                                                              : 5:151      
Azure OpenID Connect Authentication Flows (8)                                                              : 5:152      
Azure OpenID Connect Authentication Flows (9)                                                              : 5:153      
Azure OpenID Connect Flows Overview                                                                        : 5:144      
Azure OpenID OAuth Flow Types                                                                              : 5:155      
Azure Password Attacks Azure Smart Lockout                                                                 : 5:136      
Azure Password Attacks Azure Smart Lockout Customization                                                   : 5:137      
Azure Password Attacks Lockout Bypass IP Rotation (1)                                                      : 5:139      
Azure Password Attacks Lockout Bypass IP Rotation (2)                                                      : 5:140      
Azure Password Attacks Lockout Bypass Overview                                                             : 5:138      
Azure Password Attacks Password Spraying in Azure                                                          : 5:131      
Azure Password Attacks Spray365                                                                            : 5:134      
Azure Password Attacks Spray365 Usage                                                                      : 5:135      
Azure Password Attacks TrevorSpray                                                                         : 5:132      
Azure Permissions (Builtin and Custom Roles)                                                               : 5:167      
Azure Permissions Global Administrator                                                                     : 5:166      
Azure Permissions IAM Document                                                                             : 5:168      
Azure Permissions IMDS                                                                                     : 5:170      
Azure Permissions Managed Identities                                                                       : 5:171      
Azure Permissions Where are Permissions Applied?                                                           : 5:169      
Azure Recon AADInternals Overview                                                                          : 5:120      
Azure Recon AADInternals Recon                                                                             : 5:121      
Azure Recon Legacy Authentication and Protocols                                                            : 5:128      
Azure Recon Modern Authentication                                                                          : 5:129      
Azure Recon Username Enumeration Endpoints                                                                 : 5:122      
Azure Recon Username Enumeration GetCredentialType Endpoint                                                : 5:123      
Azure Recon Username Enumeration GetCredentialType Throttling                                              : 5:125      
Azure Recon Username Enumeration OAuth Token Endpoint (1)                                                  : 5:126      
Azure Recon Username Enumeration OAuth Token Endpoint (2)                                                  : 5:127      
Azure Services Overview (1)                                                                                : 5:106      
Azure Services Overview (2)                                                                                : 5:107      
Azure VM Operations                                                                                        : 5:163      
Azure VM Running Commands                                                                                  : 5:164      
BloodHound Graph Interface                                                                                 : 3:34       
BloodHound How Do We Know Where to Steal Credentials?                                                      : 3:31       
BloodHound Ingestion via SharpHound                                                                        : 3:32       
BloodHound Marking Targets (Owned, High Value)                                                             : 3:35       
BloodHound Overview                                                                                        : 3:30       
BloodHound Queries                                                                                         : 3:33       
Building Infrastructure                                                                                    : 1:33       
Building Infrastructure Building a Lab                                                                     : 1:34       
Building Infrastructure Dedicated Test Systems                                                             : 1:36       
Building Infrastructure MITRE ATT&CK                                                                       : 1:38       
Building Infrastructure Sources for Free Tools and Exploits                                                : 1:37       
Building Infrastructure Systems Used for Internal Testing                                                  : 1:35       
Building Infrastructure Tools for Penetration Testing Teams                                                : 1:39       
C2 The C2 Matrix                                                                                           : 2:73       
C2 Empire Features                                                                                         : 2:88       
C2 Empire Features Supporting Offensive Operations                                                         : 2:89       
C2 Empire Module Categories (1)                                                                            : 2:91       
C2 Empire Module Categories (2)                                                                            : 2:92       
C2 Empire Modules                                                                                          : 2:90       
C2 Empire Overview                                                                                         : 2:87       
C2 Matrix Google Sheet                                                                                     : 2:74       
C2 Sliver C2 Framewor Overview                                                                             : 2:76       
C2 Sliver Features                                                                                         : 2:77       
C2 Sliver Features Supporting Offensive Operations                                                         : 2:78       
C2 Sliver Generating Payloads                                                                              : 2:83       
C2 Sliver Implant Commands                                                                                 : 2:81       
C2 Sliver Multiplayer                                                                                      : 2:82       
C2 Sliver Payload File Format Options                                                                      : 2:79       
C2 Sliver Payload Options                                                                                  : 2:80       
C2 What is a C2 Framework                                                                                  : 2:72       
Command Prompts                                                                                            : 1:55       
DomDom and AD Persistence                                                                                  : 5:32       
DomDom Creating a Domain Admin Account                                                                     : 5:35       
DomDom DCShadow Becoming a Domain Controller                                                               : 5:40       
DomDom DCShadow Becoming a Domain Controller Example                                                       : 5:41       
DomDom DCSync Replicating the Domain Controller                                                            : 5:38       
DomDom DCSync Replicating the Domain Controller Example                                                    : 5:39       
DomDom Mimikatz Skeleton Key                                                                               : 5:36       
DomDom Mimikatz Skeleton Key in Action                                                                     : 5:37       
DomDom Obtaining Access to Back-Up NTDS.dit File                                                           : 5:33       
DomPrivEsc (AS-REP Roasting)                                                                               : 5:104      
DomPrivEsc PowerViewFind-InterestingDomainShareFile                                                        : 5:101      
DomPrivEsc PowerViewFind-LocalAdminAccess                                                                  : 5:102      
DomPrivEsc Process Memory Dumps                                                                            : 5:103      
Evasion AMSI (Antimalware Scan Interface)                                                                  : 4:56       
Evasion AMSI - AMSI Initialization                                                                         : 4:58       
Evasion AMSI - Downgrade Attacks                                                                           : 4:59       
Evasion AMSI - String Modification                                                                         : 4:60       
Evasion AMSI Initialization in PowerShell                                                                  : 4:57       
Evasion AV/EDR (Static vs Dynamic Evasion)                                                                 : 4:55       
Evasion AV/EDR Approaches                                                                                  : 4:53       
Evasion AV/EDR Call API's to Bypass Hooks (SharpBlock)                                                     : 4:63       
Evasion AV/EDR Evasion Tactics                                                                             : 4:52       
Evasion AV/EDR Signature-Based Detections                                                                  : 4:64       
Evasion AV/EDR Static Analysis Evasion                                                                     : 4:61       
Evasion AV/EDR Stripping PowerShell Comments                                                               : 4:62       
Evasion AV/EDR Tools for Automating Evasion                                                                : 4:69       
Evasion AV/EDR Windows Defender (1)                                                                        : 4:65       
Evasion AV/EDR Windows Defender (2)                                                                        : 4:66       
Evasion AV/EDR Windows Defender (3)                                                                        : 4:67       
Evasion AV/EDR Windows Defender (4)                                                                        : 4:68       
Evasion virustotal.com?                                                                                    : 4:54       
Exploitation Categories of Exploits                                                                        : 2:30       
Exploitation Client-Side Commonly Vulnerable Software                                                      : 2:33       
Exploitation Client-Side Exploits                                                                          : 2:32       
Exploitation Client-Side Exploits and Guardrails                                                           : 2:35       
Exploitation Local PrivEsc Attack Categories and Suites                                                    : 2:39       
Exploitation Local PrivEsc Exploits                                                                        : 2:38       
Exploitation Mounting a Client-Side Exploitation Campaign                                                  : 2:34       
Exploitation Risks of Exploitation                                                                         : 2:28       
Exploitation Server-Side Exploits                                                                          : 2:31       
Exploitation Use Appropriate, Representative Client Machines                                               : 2:37       
Exploitation Using Payloads on Target Systems                                                              : 2:36       
Exploitation What Is Exploitation?                                                                         : 2:26       
Exploitation Why use Exploitation?                                                                         : 2:27       
EyeWitness                                                                                                 : 1:140      
EyeWitness Report Content                                                                                  : 1:142      
EyeWitness Specifying Targets                                                                              : 1:141      
EyeWitness What to Look For                                                                                : 1:143      
Impacket Extracting Hashes (secretsdump.py)                                                                : 4:34       
Impacket Kerberos (GetUserSPNs, ticketer).py                                                               : 4:33       
Impacket Overview                                                                                          : 4:32       
Impacket Remote Execution (ps, smb, at, wmi, dcom)exec.py                                                  : 4:35       
Impacket smbexec.py vs wmiexec.py                                                                          : 4:37       
Impacket Syntax                                                                                            : 4:36       
Initial Access Background                                                                                  : 2:5        
Initial Access Where Does Access Come From                                                                 : 2:6        
Kerberoasting AES vs. RC4                                                                                  : 5:22       
Kerberoasting Attack Overview                                                                              : 5:18       
Kerberoasting Attack Steps                                                                                 : 5:21       
Kerberoasting Obtaining Tickets (Tools)                                                                    : 5:20       
Kerberoasting Requesting a Service Ticket (ST) Revisited                                                   : 5:16       
Kerberoasting Requesting a Ticket                                                                          : 5:17       
Kerberoasting Setspn.exe                                                                                   : 5:19       
Kerberoasting What Service Accounts are Good Targets?                                                      : 5:23       
Kerberos AS-REQ with pre-authentication                                                                    : 5:9        
Kerberos Golden Ticket Flow                                                                                : 5:95       
Kerberos Golden Ticket Generation Tools (ticketer.py, mimikatz)                                            : 5:97       
Kerberos Golden Ticket Overview                                                                            : 5:30,5:94  
Kerberos Golden Ticket Properties                                                                          : 5:96       
Kerberos How It Works                                                                                      : 5:6        
Kerberos Introduction                                                                                      : 5:5        
Kerberos Overall Flow                                                                                      : 5:7        
Kerberos Overpass-the-Hash                                                                                 : 5:29       
Kerberos Pass-the-Ticket                                                                                   : 5:27       
Kerberos Pass-the-Ticket Mimikatz Example                                                                  : 5:28       
Kerberos Service Principal Name                                                                            : 5:12       
Kerberos Silver Ticket Generation Impacket ticketer.py                                                     : 5:89       
Kerberos Silver Ticket Overview                                                                            : 5:87       
Kerberos Silver Ticket Service Ticket and PAC                                                              : 5:88       
Kerberos Silver Ticket Use on Linux and Windows                                                            : 5:90       
Kerberos ST Requesting a Service Ticket                                                                    : 5:11       
Kerberos ST Service Ticket                                                                                 : 5:14       
Kerberos ST Using a Service Ticket                                                                         : 5:13       
Kerberos TGT (Ticket Granting Ticket) and PAC                                                              : 5:10       
Kerberos Three Long-Term Keys (KDC, Client, Target Service)                                                : 5:8        
LatMov Linux (Cred Reuse, SSO, SSH key theft)                                                              : 4:6        
LatMov Pivoting Metasploit Meterpreter Autoroute                                                           : 4:86       
LatMov Pivoting Metasploit Meterpreter Port Forwarding                                                     : 4:85       
LatMov Pivoting Metasploit route Command                                                                   : 4:84       
LatMov Pivoting SSH Dynamic Port Forwarding                                                                : 4:88       
LatMov Pivoting SSH Local Port Forwarding                                                                  : 4:87       
LatMov Why Lateral Movement?                                                                               : 4:5        
LatMov Windows (LOL, RDP, WMI, WinRM, PsExec, ticket/hash reuse)                                           : 4:8        
LatMov Windows Command Line for Penetration Testers                                                        : 4:9        
LatMov Windows Remote Management (WinRM)                                                                   : 4:10       
LatMov Windows Run Cmds Metasploit PsExec Module                                                           : 4:20       
LatMov Windows Run Cmds on Remote Systems Methods                                                          : 4:17       
LatMov Windows Run Cmds SC Invoke an Executable                                                            : 4:23       
LatMov Windows Run Cmds SC Make Executable a Service                                                       : 4:24       
LatMov Windows Run Cmds schtasks Run an Executable                                                         : 4:22       
LatMov Windows Run Cmds schtasks Scheduling a Job                                                          : 4:21       
LatMov Windows Run Cmds Sysinternals PsExec.exe (1)                                                        : 4:18       
LatMov Windows Run Cmds Sysinternals PsExec.exe (2)                                                        : 4:19       
LatMov Windows Run Cmds WMIC Interacting with Processes                                                    : 4:26       
LatMov Windows Run Cmds WMIC Invoke a Program                                                              : 4:25       
LatMov Windows SC Controlling Services with SC                                                             : 4:14       
LatMov Windows SC Determining Service Names                                                                : 4:16       
LatMov Windows SC Starting and Stopping Services                                                           : 4:15       
LatMov Windows SMB Session Setup                                                                           : 4:13       
LatMov Windows Ticket Reuse                                                                                : 4:12       
LatMov Windows WinRM and PowerShell                                                                        : 4:11       
Linux Commands for Pen Testers                                                                             : 1:53       
Linux Escalating with SETUID                                                                               : 1:51       
Linux Escalation                                                                                           : 1:52       
Linux File System Structure                                                                                : 1:46       
Linux Fun Ease-of-Use Shell Tips                                                                           : 1:43       
Linux Listing Files                                                                                        : 1:49       
Linux Navigating the Filesystem                                                                            : 1:48       
Linux Permissions                                                                                          : 1:50       
Linux Software for Testing: Prepackaged Testing Suites                                                     : 1:54       
Linux Users: Root and Non-root                                                                             : 1:44       
Linux vs.Windows                                                                                           : 1:42       
Linux Where Am I?                                                                                          : 1:47       
Linux Who Am I?                                                                                            : 1:45       
Masscan                                                                                                    : 1:123      
Masscan Extracting Live Hosts and Open Ports                                                               : 1:125      
Masscan Output                                                                                             : 1:124      
Masscan vs Nmap Faster Scanning                                                                            : 1:122      
Metasploit Design                                                                                          : 2:42       
Metasploit Exploit Arsenal                                                                                 : 2:45       
Metasploit Exploit Rankings                                                                                : 2:47       
Metasploit Exploitation Framework                                                                          : 2:41       
Metasploit Modules (exploits, payloads, auxiliary, post)                                                   : 2:44       
Metasploit Modules: Payloads                                                                               : 2:48       
Metasploit Payloads: Windows Singles                                                                       : 2:49       
Metasploit Payloads: Windows Stagers                                                                       : 2:50       
Metasploit Payloads: Windows Stages                                                                        : 2:51       
Metasploit User Interfaces                                                                                 : 2:43       
Metasploit Windows Exploits                                                                                : 2:46       
Meterpreter Functionality: Additional Modules                                                              : 2:60       
Meterpreter Functionality: File System Commands                                                            : 2:55       
Meterpreter Functionality: Keystroke Logger                                                                : 2:58       
Meterpreter Functionality: Pivoting Using Route                                                            : 2:59       
Meterpreter Functionality: Process Commands                                                                : 2:54       
Meterpreter Functionality: Some Base Commands                                                              : 2:53       
Meterpreter Functionality:Target Machine Console                                                           : 2:57       
Meterpreter Overview                                                                                       : 2:52       
Meterpreter Stdapi Capabilities: Networking Commands                                                       : 2:56       
Netcat Automating Service String Information                                                               : 1:136      
Netcat Client Grabbing Service Info                                                                        : 1:135      
Netcat Command Flags                                                                                       : 1:134      
Netcat for the Pen Tester                                                                                  : 1:133      
Netcat Moving Files                                                                                        : 1:138      
Netcat uses a Lowercase L                                                                                  : 1:137      
Ngrok Example Flow                                                                                         : 5:177      
Ngrok How it Works                                                                                         : 5:176      
Ngrok Overview                                                                                             : 5:175      
Ngrok Visualization of ngrok                                                                               : 5:178      
Nmap Active OS Fingerprinting                                                                              : 1:129      
Nmap and Address Probing                                                                                   : 1:112      
Nmap Input and Output Options                                                                              : 1:111      
Nmap Limitations and Host Groups                                                                           : 1:121      
Nmap Network Probe/Sweeping Options                                                                        : 1:113      
Nmap NSE Script Categories                                                                                 : 1:155      
Nmap Optimizing Host Detection                                                                             : 1:114      
Nmap Port Scanner                                                                                          : 1:109      
Nmap Port Scanning (After Host Detection)                                                                  : 1:115      
Nmap Scripting Engine                                                                                      : 1:153      
Nmap Scripting Engine Scripts                                                                              : 1:154      
Nmap Some Example NSE Scripts                                                                              : 1:156      
Nmap TCP Port Scan Types: Connect Scan                                                                     : 1:116      
Nmap UDP Scans                                                                                             : 1:117      
Nmap Version Scan as Vulnerability Scanner?                                                                : 1:151      
Nmap Version Scanning                                                                                      : 1:130      
Nmap Version Scanning Functionality                                                                        : 1:131      
Nmap's Timing Options                                                                                      : 1:110      
Pass-the-Hash Advantages                                                                                   : 4:42       
Pass-the-Hash C2 Frameworks                                                                                : 4:45       
Pass-the-Hash Metasploit PsExec Module                                                                     : 4:46       
Pass-the-Hash Microsoft's Mitigations                                                                      : 4:44       
Pass-the-Hash NTLMv2 Graphically                                                                           : 4:43       
Pass-the-Hash Technique Overview                                                                           : 4:41       
Password Attacks: When to Use Each Technique (with/out hashes)                                             : 4:47       
Password Cracking Alts (Sniffing, Keyloggers, Pass-the-Hash)                                               : 3:54       
Password Cracking Considerations                                                                           : 3:55       
Password Cracking Custom Dictionaries                                                                      : 3:51       
Password Cracking Dictionaries                                                                             : 3:50       
Password Cracking Hashcat Dictionaries, and Word Mangling Rules                                            : 3:91       
Password Cracking Hashcat Mask Examples                                                                    : 3:93       
Password Cracking Hashcat Masks                                                                            : 3:92       
Password Cracking Hashcat Multithreaded and GPU                                                            : 3:88       
Password Cracking Hashcat Potfile, Show, and Restore                                                       : 3:90       
Password Cracking Hashcat Specifying Hash Types                                                            : 3:89       
Password Cracking Hashcat Status and Temp Sensor                                                           : 3:94       
Password Cracking Improving Speed                                                                          : 3:53       
Password Cracking John Config File and Cracking Modes                                                      : 3:82       
Password Cracking John Interpreting Output                                                                 : 3:84       
Password Cracking John john.pot File                                                                       : 3:83       
Password Cracking John Speed                                                                               : 3:85       
Password Cracking John the Ripper                                                                          : 3:81       
Password Cracking John vs. Hashcat                                                                         : 3:86       
Password Cracking Pipal Password Pattern Analysis                                                          : 3:95       
Password Cracking Reporting                                                                                : 3:56       
Password Cracking Synced Passwords                                                                         : 3:49       
Password Cracking Update Your Dictionary                                                                   : 3:52       
Password Cracking vs. Password Guessing                                                                    : 3:48       
Password Dumping Hashes with Meterpreter                                                                   : 3:73       
Password Dumping Linux/UNIX Password Representations                                                       : 3:71       
Password Dumping Windows from mimikatz Kiwi                                                                : 3:77       
Password Dumping Windows NTDSUtil                                                                          : 3:76       
Password Dumping Windows Password Representations                                                          : 3:72       
Password Dumping Windows VSS Extract of ntds.dit                                                           : 3:75       
Password Dumping Windows VSS Volume Shadow Copy Service (ntds.dit+                                         : 3:74       
Password Guessing Account Lockout                                                                          : 2:15       
Password Guessing Account Lockout on Windows                                                               : 2:16       
Password Guessing Active Directory Lockout Scenario                                                        : 2:17       
Password Guessing Credential Databases                                                                     : 2:10       
Password Guessing Credential Stuffing                                                                      : 2:9        
Password Guessing Guessing Usernames                                                                       : 2:14       
Password Guessing Hydra                                                                                    : 2:20       
Password Guessing Hydra Examples                                                                           : 2:21       
Password Guessing Hydra with the Domain                                                                    : 2:22       
Password Guessing The Importance of Passwords                                                              : 2:8        
Password Guessing Suggested Spray Technique                                                                : 2:18       
Password Guessing Tools                                                                                    : 2:19       
Password Guessing Trimming Word Lists with Hydra's pw-inspector                                            : 2:13       
Password Guessing Types of Online Password Attacks                                                         : 2:11       
Password Guessing with a Custom Dictionary                                                                 : 2:12       
Password Reprs Linux and UNIX Password Representations                                                     : 3:68       
Password Reprs Linux MD5-Based Password Scheme                                                             : 3:69       
Password Reprs Windows AD (ntds.dit)                                                                       : 3:59       
Password Reprs Windows CAC and Smartcards                                                                  : 3:67       
Password Reprs Windows Challenge/Response on the Network                                                   : 3:62       
Password Reprs Windows LANMAN and NTLMv1 Challenge/Response                                                : 3:64       
Password Reprs Windows LANMAN Challenge/Response                                                           : 3:63       
Password Reprs Windows LANMAN Hash Algorithm                                                               : 3:60       
Password Reprs Windows NT Hash Algorithm                                                                   : 3:61       
Password Reprs Windows NTLMv2 Challenge/Response                                                           : 3:65       
Password Reprs Windows NTLMv2 Graphically                                                                  : 3:66       
Password Reprs Windows SAM Database                                                                        : 3:58       
Payloads Common Payload Types                                                                              : 2:97       
Payloads DDE                                                                                               : 2:100      
Payloads ISO                                                                                               : 2:101      
Payloads LNK Files                                                                                         : 2:103      
Payloads Overview                                                                                          : 2:96       
Payloads Using Macros                                                                                      : 2:98       
Payloads VBA                                                                                               : 2:99       
Payloads Zip File                                                                                          : 2:102      
Persistence Why Persistence                                                                                : 3:39       
Persistence Windows Registry                                                                               : 3:40       
Persistence Windows Scheduled Task                                                                         : 3:42       
Persistence Windows Services                                                                               : 3:43       
Persistence Windows Startup Folder                                                                         : 3:41       
Persistence Windows WMI Event Consumer                                                                     : 3:44       
Post Exploitation Tactics                                                                                  : 2:108      
Post-Exploitation Activities                                                                               : 2:107      
Post-Exploitation File Transfer (Copy/Paste to Move Files)                                                 : 2:112      
Post-Exploitation File Transfer (HTTP, SCP, FTP, TFTP)                                                     : 2:109      
Post-Exploitation File Transfer (Meterpreter)                                                              : 2:111      
Post-Exploitation File Transfer (SMB, NFS mounts, Netcat)                                                  : 2:110      
Pre-Engagement Announced vs. Unannounced Tests                                                             : 1:25       
Pre-Engagement Documented Permission                                                                       : 1:20       
Pre-Engagement Goals                                                                                       : 1:22       
Pre-Engagement Kickoff Call                                                                                : 1:28       
Pre-Engagement Penetration Testing Process Phases                                                          : 1:19       
Pre-Engagement Rules of Engagement                                                                         : 1:24       
Pre-Engagement Scope                                                                                       : 1:23       
Pre-Engagement Steps                                                                                       : 1:21       
Pre-Engagement Viewing Data on Compromised Systems                                                         : 1:27       
Pre-Engagement Zero-Knowledge vs. Full-Knowledge Testing                                                   : 1:26       
PrivEsc Linux GTFOBins                                                                                     : 3:12       
PrivEsc Linux Kernel Exploits                                                                              : 3:8        
PrivEsc Linux PrivEsc Linux World Writeable Files                                                          : 3:10       
PrivEsc Linux Services Running as Root                                                                     : 3:9        
PrivEsc Linux SETUID                                                                                       : 3:11       
PrivEsc Linux Why Linux?                                                                                   : 3:7        
PrivEsc Why PrivEsc?                                                                                       : 3:5        
PrivEsc Windows Common Flaws                                                                               : 3:14       
PrivEsc Windows Group Policy Preference (GPP)                                                              : 3:18       
PrivEsc Windows Group Policy Preference (GPP) Files                                                        : 3:17       
PrivEsc Windows LOLBAS                                                                                     : 3:26       
PrivEsc Windows PowerUp                                                                                    : 3:25       
PrivEsc Windows Tools (BeRoot, Watson, PowerUp)                                                            : 3:24       
PrivEsc Windows UAC Bypass Techniques                                                                      : 3:23       
PrivEsc Windows UAC Levels                                                                                 : 3:22       
PrivEsc Windows Unattended Install Files                                                                   : 3:15       
PrivEsc Windows Unattended Install Files Contents                                                          : 3:16       
PrivEsc Windows Unquoted Paths with Spaces (1)                                                             : 3:19       
PrivEsc Windows Unquoted Paths with Spaces (2)                                                             : 3:20       
PrivEsc Windows User Account Control (UAC)                                                                 : 3:21       
Recon Infra Certificate Transparency Logs                                                                  : 1:79       
Recon Infra DNSDumpster                                                                                    : 1:75       
Recon Infra DNSDumpster Usage (1)                                                                          : 1:76       
Recon Infra DNSDumpster Usage (2)                                                                          : 1:77       
Recon Infra DNSRecon                                                                                       : 1:73       
Recon Infra DNSRecon Usage                                                                                 : 1:74       
Recon Infra Hostname Information                                                                           : 1:72       
Recon Infra Shodan                                                                                         : 1:80       
Recon Infra WHOIS + Regional Internet Registries                                                           : 1:78       
Recon Infrastructure                                                                                       : 1:71       
Recon Motivation                                                                                           : 1:61       
Recon Org Gather Competitive Intelligence                                                                  : 1:69       
Recon Org Information on the Organization                                                                  : 1:67       
Recon Org Press Releases and Annual Reports                                                                : 1:68       
Recon Social Engineering and Ethics                                                                        : 1:64       
Recon Targets                                                                                              : 1:63       
Recon Traffic                                                                                              : 1:62       
Recon User GatherContacts                                                                                  : 1:88       
Recon User GatherContacts Results                                                                          : 1:89       
Recon User Hunter.io                                                                                       : 1:83       
Recon User LinkedIn can provide a lot of information on employees                                          : 1:87       
Recon User Look for Open Job Requisitions                                                                  : 1:86       
Recon User phonebook.cz lists emails, URLs for a domain                                                    : 1:84       
Recon User Public Breach Data of Credentials                                                               : 1:85       
Reporting 1. Executive Summary (1)                                                                         : 4:97       
Reporting 1. Executive Summary (2)                                                                         : 4:98       
Reporting 2. Introduction                                                                                  : 4:99       
Reporting 3. Findings                                                                                      : 4:100      
Reporting 3. Findings Order                                                                                : 4:112      
Reporting 3. Findings Screenshot Elements                                                                  : 4:102      
Reporting 3. Findings Screenshot to Illustrate Findings                                                    : 4:101      
Reporting 3. Findings Screenshot Tools                                                                     : 4:103      
Reporting 4. Methodology                                                                                   : 4:108      
Reporting Always Create a Report                                                                           : 4:94       
Reporting Appendices                                                                                       : 4:109      
Reporting Be Consistent!                                                                                   : 4:113      
Reporting Clean and Succinct Reporting                                                                     : 4:116      
Reporting Don't Just Regurgitate Vuln Scan Results                                                         : 4:95       
Reporting Effective Illustrations                                                                          : 4:118      
Reporting Readability                                                                                      : 4:115      
Reporting Recommendations                                                                                  : 4:105      
Reporting Recommended Reading                                                                              : 4:110      
Reporting Recommended Report Format                                                                        : 4:96       
Reporting Redaction and Transparency                                                                       : 4:104      
Reporting Sample Reports                                                                                   : 4:111      
Reporting Styles and Themes                                                                                : 4:114      
Reporting Use of Colors                                                                                    : 4:117      
Reporting Validation and Verification                                                                      : 4:107      
Scanning Goals of Scanning Phase                                                                           : 1:93       
Scanning Handling Large Scans by Limiting Scope                                                            : 1:96       
Scanning Port Handshake Happens Regardless of Higher-Level Protocol                                        : 1:102      
Scanning Port Protocol Layers and TCP vs. UDP                                                              : 1:98       
Scanning Port TCP Behavior (1)                                                                             : 1:103      
Scanning Port TCP Behavior (2):                                                                            : 1:104      
Scanning Port TCP Flags                                                                                    : 1:100      
Scanning Port TCP Header                                                                                   : 1:99       
Scanning Port TCP Three-Way Handshake                                                                      : 1:101      
Scanning Port UDP Behavior (1)                                                                             : 1:106      
Scanning Port UDP Behavior (2)                                                                             : 1:107      
Scanning Port UDP Header                                                                                   : 1:105      
Scanning Scan Types                                                                                        : 1:94       
Scanning Tip: Dealing with Very Large Scans                                                                : 1:95       
Scanning Vulns Methods for Discovering Vulnerabilities (1)                                                 : 1:145      
Scanning Vulns Methods for Discovering Vulnerabilities (2)                                                 : 1:146      
Scanning Vulns Safe Checks and Dangerous Plugins                                                           : 1:149      
Scanning Vulns Scan Results                                                                                : 1:150      
Scanning Vulns Scan Types                                                                                  : 1:148      
Scanning Vulns Scanner Goals                                                                               : 1:147      
Situational Awareness File Pilfering                                                                       : 2:115      
Situational Awareness Linux Accounts                                                                       : 2:118      
Situational Awareness Linux Groups                                                                         : 2:119      
Situational Awareness Linux Interesting Files (1)                                                          : 2:120      
Situational Awareness Linux Interesting Files (2)                                                          : 2:121      
Situational Awareness Linux Local File Pilfering                                                           : 2:122      
Situational Awareness Network Pilfering                                                                    : 2:116      
Situational Awareness Overview                                                                             : 2:114      
Situational Awareness Windows AD Explorer                                                                  : 2:135      
Situational Awareness Windows Deleting Users and Accounts                                                  : 2:130      
Situational Awareness Windows Determining Firewall Settings                                                : 2:131      
Situational Awareness Windows Displaying and Searching Files                                               : 2:132      
Situational Awareness Windows Domain Groups                                                                : 2:129      
Situational Awareness Windows Domain User                                                                  : 2:127      
Situational Awareness Windows Environment Variables                                                        : 2:124      
Situational Awareness Windows Interacting with the Registry                                                : 2:133      
Situational Awareness Windows Local Groups                                                                 : 2:128      
Situational Awareness Windows Managing Accounts and Groups                                                 : 2:126      
Situational Awareness Windows PowerView                                                                    : 2:134      
Situational Awareness Windows Searching the File System                                                    : 2:125      
Situational Awareness Windows Seatbelt Command Groups                                                      : 2:139      
Situational Awareness Windows Seatbelt Executing Checks                                                    : 2:138      
Situational Awareness Windows Seatbelt GhostPack Overview                                                  : 2:137      
Sniff/Relay Kerberos and NTLMv2                                                                            : 3:99       
Sniff/Relay NTLMv2 Attack Strategies                                                                       : 3:100      
Sniff/Relay PCredz Cracking Process                                                                        : 3:102      
Sniff/Relay PCredz Extracting Hashes                                                                       : 3:103      
Sniff/Relay PCredz Getting the Hashes from Log File                                                        : 3:104      
Sniff/Relay Resonder Defenses                                                                              : 3:113      
Sniff/Relay Resonder NTLM Offline Brute Force Hashcat                                                      : 3:110      
Sniff/Relay Resonder NTLM SMB Relaying                                                                     : 3:111      
Sniff/Relay Resonder NTLM SMB Relaying with Responder                                                      : 3:112      
Sniff/Relay Resonder Obtain NetNTLMv2 Challenge/Response                                                   : 3:107      
Sniff/Relay Resonder Obtain NetNTLMv2 Other Tricks                                                         : 3:109      
Sniff/Relay Resonder Overview                                                                              : 3:106      
Sniff/Relay Resonder Web Proxy Autodiscovery Protocol                                                      : 3:108      
Sniff/Relay Windows Challenge/Response                                                                     : 3:101      
Terms Attack Phases                                                                                        : 1:17       
Terms Pen Test, Red Team, Purple Team, Audit                                                               : 1:13       
Terms Penetration Testing Goals                                                                            : 1:15       
Terms Threat Risk                                                                                          : 1:12       
Terms Types of Penetration Tests                                                                           : 1:16       
Terms Vulnerability Assessment, Security Audit                                                             : 1:14       
Terms Vulnerability, Exploit                                                                               : 1:11       
```