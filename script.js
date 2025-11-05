// ===============================================
// SACHIDAX Learning Explorer — D3 v7 Multi-map
// ===============================================

// ----------- 1) DATASETS (networking + cybersecurity) -----------

const DATASETS = {
  networking: {
    name: "Networking Mastery Tree Map",
    short: "Visual learning map: explore concepts, tools, and career paths in networking.",
    level: "All",
    children: [
      {
        name: "Foundations",
        short: "Understand the basics of computer networks",
        level: "Beginner",
        children: [
          { name: "OSI Model", short: "7-layer model fundamentals", level: "Beginner" },
          { name: "IP Addressing", short: "IPv4, IPv6, subnetting", level: "Beginner" },
          { name: "Protocols", short: "TCP, UDP, HTTP, DNS, DHCP", level: "Beginner" }
        ]
      },
      {
        name: "Intermediate Networking",
        short: "Routing, switching, and wireless",
        level: "Intermediate",
        children: [
          { name: "Routing", short: "Static, dynamic routing, OSPF, BGP", level: "Intermediate" },
          { name: "Switching", short: "VLANs, trunking, STP", level: "Intermediate" },
          { name: "Wireless", short: "802.11 standards, Wi-Fi security", level: "Intermediate" }
        ]
      },
      {
        name: "Advanced Topics",
        short: "Automation, monitoring, cloud networking",
        level: "Advanced",
        children: [
          { name: "Network Automation", short: "Python, Ansible, SDN", level: "Advanced" },
          { name: "Network Security", short: "Firewalls, IDS/IPS, VPN", level: "Advanced" },
          { name: "Cloud Networking", short: "AWS VPC, Azure VNets", level: "Advanced" }
        ]
      }
    ]
  },

  cybersecurity: CYBERSECURITY_DATA // from your provided full roadmap earlier
};

// ----------- 2) GLOBAL D3 SETUP -----------

const svg = d3.select("#treeSvg");
const wrap = document.getElementById("treewrap");
const infopane = document.getElementById("infopane");
const width = wrap.clientWidth;
const height = wrap.clientHeight;
svg.attr("viewBox", [0, 0, width, height]);

const g = svg.append("g").attr("transform", "translate(40,0)");
const zoom = d3.zoom().scaleExtent([0.5, 2]).on("zoom", (e) => g.attr("transform", e.transform));
svg.call(zoom);

let root;
const tree = d3.tree().size([height, width - 260]);
let idCounter = 0;

// ----------- 3) DRAW FUNCTION -----------

function drawTree(data) {
  svg.selectAll("*").remove();
  const gLinks = svg.append("g").attr("class", "links");
  const gNodes = svg.append("g").attr("class", "nodes");

  root = d3.hierarchy(data);
  root.x0 = height / 2;
  root.y0 = 0;

  function collapse(d) {
    if (d.children) {
      d._children = d.children;
      d._children.forEach(collapse);
      d.children = null;
    }
  }
  if (root.children) root.children.forEach(collapse);

  update(root);

  function update(source) {
    tree(root);
    const nodes = root.descendants();
    const links = root.links();

    const nodeSel = gNodes.selectAll("g.node")
      .data(nodes, (d) => d.data.__id || (d.data.__id = ++idCounter));

    const nodeEnter = nodeSel.enter().append("g")
      .attr("class", "node")
      .attr("transform", (d) => `translate(${source.y0},${source.x0})`)
      .on("click", (event, d) => {
        d.children = d.children ? null : d._children;
        update(d);
        showDetails(d.data);
      });

    nodeEnter.append("circle")
      .attr("r", 1e-6)
      .attr("fill", "#58a6ff")
      .attr("stroke", "#30363d")
      .attr("stroke-width", 1.2);

    nodeEnter.append("text")
      .attr("dy", "0.32em")
      .attr("x", 10)
      .attr("fill", "#dceeff")
      .style("font-size", 12)
      .text((d) => d.data.name);

    const nodeUpdate = nodeEnter.merge(nodeSel);
    nodeUpdate.transition().duration(350).attr("transform", (d) => `translate(${d.y},${d.x})`);
    nodeUpdate.select("circle").transition().duration(350).attr("r", 7);

    const linkSel = gLinks.selectAll("path.link")
      .data(links, (d) => d.target.data.__id);

    linkSel.exit().transition().duration(300).style("opacity", 0).remove();

    linkSel.enter()
      .append("path")
      .attr("class", "link")
      .attr("fill", "none")
      .attr("stroke", "#444")
      .attr("stroke-width", 1.3)
      .attr("d", (d) => {
        const o = { x: source.x0, y: source.y0 };
        return d3.linkHorizontal().x((d) => d.y).y((d) => d.x)({ source: o, target: o });
      })
      .merge(linkSel)
      .transition()
      .duration(350)
      .attr("d", (d) => d3.linkHorizontal().x((d) => d.y).y((d) => d.x)(d));

    nodes.forEach((d) => {
      d.x0 = d.x;
      d.y0 = d.y;
    });
  }
}

// ----------- 4) INFO PANEL -----------

function showDetails(data) {
  document.getElementById("nodeTitle").textContent = data.name || "—";
  document.getElementById("nodeShort").textContent = data.short || "—";
  document.getElementById("nodeLevel").textContent = data.level || "—";
  const toolsDiv = document.getElementById("nodeTools");
  toolsDiv.innerHTML = "";
  if (Array.isArray(data.tools)) {
    data.tools.forEach((t) => {
      const s = document.createElement("span");
      s.className = "tag";
      s.textContent = t;
      toolsDiv.appendChild(s);
    });
  }
}

// ----------- 5) INIT + SWITCHER -----------

const selector = document.getElementById("mapSelector");
selector.addEventListener("change", () => {
  const key = selector.value;
  drawTree(DATASETS[key]);
});

drawTree(DATASETS.networking);
