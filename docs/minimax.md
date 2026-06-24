# Building an Agentic Security Analysis Agent — Research Synthesis & Build Plan

> **Scope:** Synthesizes the latest academic and industry work on LLM-powered security agents (penetration testing, vulnerability detection, code analysis, defensive security ops) and distills it into a concrete architecture and build roadmap.
>
> **Key reading:** PentestGPT (USENIX Sec '24), HPTSA ("Teams of LLM Agents can Exploit Zero-Day Vulnerabilities"), Incalmo (multi-host red team), SEC-bench (NeurIPS '25), CVE-Bench (ICML '25), CyKG-RAG, MCP safety audits (Apr '25), OWASP LLM Top 10 (Nov '24) and OWASP Top 10 for Agentic Applications (Dec '25).

---

## 1. Where the field actually stands (mid-2026)

Three archetypes have crystallized in the literature, and you should pick which one(s) you want to build first.

### 1.1 Offensive / pentesting agents
- **PentestGPT** (Deng et al., USENIX Sec '24, arXiv:2308.06782) — Three cooperating LLM sessions: a **Reasoning** module that maintains the high-level plan, a **Generation** module that produces concrete next-step commands, and a **Parsing** module that converts tool output into structured state. 228.6% task-completion lift over vanilla GPT-3.5 on HackTheBox-style benchmarks. Still struggles with long-horizon context.
- **HPTSA / "Teams of LLM Agents"** (arXiv:2406.01637, EACL '26) — Hierarchical Planning + Task-Specific Agents. A **Planner** explores the target and decides which specialist to spin up; **specialist agents** focus on one vuln class (SQLi, XSS, SSRF); a **team manager** coordinates. **4.3× lift** over single-agent baselines; hacked 8/15 real-world zero-days with GPT-4. Most-cited evidence that *teams* beat *heroes* in this domain.
- **PentestAgent** (arXiv:2411.05185) — Reinforces the multi-agent split with classical planning techniques.
- **Incalmo** (arXiv:2501.16466, CMU) — Focused on **multi-host enterprise networks** (post-compromise lateral movement), where PentestGPT/HPTSA fail. Key innovation: an **LLM-agnostic high-level attack abstraction layer** that translates natural-language plans into concrete primitives (scan_host, find_credentials, move_laterally). Solved 9/10 enterprise scenarios (25–50 hosts). This pattern matters for you.
- **CRAKEN** (OpenReview) — Cybersecurity-specific LLM agent with structured knowledge for threat modeling, vuln analysis, exploit execution.

### 1.2 Defensive / code & repo analysis agents
- **SEC-bench** (arXiv:2506.11791, NeurIPS '25) — The cleanest benchmark: a **multi-agent scaffold** that auto-builds vulnerable repos, runs PoC generation and patching tasks against real CVEs, costs $0.87/instance. State-of-the-art agents hit **18% PoC-gen success and 34% patch success** — so the headroom is huge.
- **CVE-Bench** (arXiv:2503.17332, ICML '25 Spotlight) — 40 critical CVEs, sandboxed web apps. Best LLM agent resolves only **13% of vulnerabilities**. The current frontier is genuinely weak at *real* exploits, not CTF toys.
- **ZeroDayBench** — Evaluates defense-side agents on previously-unseen zero-days.
- **PrimeVul** (ICSE '25) — Training/eval data for vulnerability detection code LMs; SOTA 7B model scores 68.26% F1.
- **LLM-Assisted Static Analysis** (Li et al., 2025) — Concrete techniques for using LLMs to triage Semgrep/CodeQL output.

### 1.3 Blue-team / SecOps agents
- Less academic coverage, but the industry has converged on **agentic SOAR** patterns — auto-triage alerts, correlate IOCs, draft response playbooks, query SIEM/EDR via tool calls.
- CyKG-RAG and CVE-KGRAG show the value of grounding the agent in a structured cybersecurity knowledge graph (CVE + CWE + CAPEC + ATT&CK nodes).

### Reality check
Every serious benchmark agrees: **even with the best 2026 agents, you get ~10–35% success on real-world security tasks**. The agents are useful as **force multipliers for skilled analysts**, not as autonomous replacements. Build with that expectation or you'll be disappointed.

---

## 2. The architecture that actually works

The 2025–2026 literature has converged on a pattern. Here's what I'd recommend you build, distilled from P-t-E architectures, HPTSA, Incalmo, AWS Security Agent, and the "Architecting Resilient LLM Agents" guide (arXiv:2509.08646).

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Agent System                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────────┐   ┌──────────────┐   ┌────────────────┐  │
│   │  Planner    │──▶│  Specialist  │──▶│   Verifier /   │  │
│   │  (LLM)      │   │  Workers     │   │   Critic       │  │
│   │             │◀──│  (LLM+tools) │◀──│   (LLM)        │  │
│   └─────────────┘   └──────────────┘   └────────────────┘  │
│          │                  │                    │         │
│          ▼                  ▼                    ▼         │
│   ┌──────────────────────────────────────────────────────┐ │
│   │        Tool / Execution Layer (MCP servers)          │ │
│   │  Semgrep · CodeQL · Burp · Nmap · Nuclei · Trivy ·   │ │
│   │  Shodan · BloodHound · Metasploit · custom scripts   │ │
│   └──────────────────────────────────────────────────────┘ │
│          │                                                 │
│          ▼                                                 │
│   ┌──────────────────────────────────────────────────────┐ │
│   │   Sandboxed Execution Runtime (Docker/gVisor/Firecracker)│
│   └──────────────────────────────────────────────────────┘ │
│                                                             │
│   ┌──────────────────────────────────────────────────────┐ │
│   │   Knowledge Layer (Hybrid RAG)                       │ │
│   │   Vector store (docs, advisories) + KG (CVE/CWE/ATT&CK)│ │
│   └──────────────────────────────────────────────────────┘ │
│                                                             │
│   ┌──────────────────────────────────────────────────────┐ │
│   │   Memory: short-term task state + long-term knowledge│ │
│   └──────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Why this shape (not ReAct)
- **Plan-then-Execute beats ReAct on multi-step security work.** ReAct stalls because each tool call forces a fresh reasoning step; on a 15-step recon-to-exploit chain that's slow, expensive, and the model loses the thread. P-t-E separates strategic planning from tactical execution — you plan once, then execute deterministically with periodic re-planning. (Source: arXiv:2509.08646.)
- **A verifier/critic is non-optional.** SEC-bench's gold-patch evaluator and Incalmo's explicit "is the host actually compromised?" checks show that without an external verifier, agents hallucinate success. Add a separate model pass (or rule-based checks) that evaluates every claim.
- **Tools live behind an abstraction layer** (Incalmo pattern). Don't let the LLM call `nmap` directly with a free-form string. Define typed primitives (`scan_host(target: str, profile: str) -> ScanResult`) and let the LLM compose them. This cuts hallucinated flags, makes actions auditable, and gives you a clean place to enforce permissions.
- **Knowledge layer should be hybrid, not pure vector RAG.** CyKG-RAG and CVE-KGRAG both show that for security, you need a **vector store for unstructured context + a knowledge graph for CVE/CWE/CAPEC/ATT&CK relationships**. Pure text RAG misses that e.g. CVE-2024-X is *caused by* CWE-89, which is *exploited by* CAPEC-66.
- **Memory has two tiers.** Short-term = current task state (what hosts are compromised, what creds we have). Long-term = prior findings, project context, threat-intel updates. Don't conflate them.

### Concrete component choices
- **Orchestration:** **LangGraph** (graph-based, transparent, easy to add verifier edges) or **AutoGen** (Microsoft, conversation-centric). CrewAI is fine for simple role splits but harder to enforce control flow. AWS Security Agent and academic P-t-E work both lean LangGraph.
- **Reasoning model:** GPT-4-class or Claude-3.5/4-class for planning; can downgrade to a smaller model for execution and verification to save cost.
- **Tool protocol:** **MCP (Model Context Protocol)**. Anthropic's open standard, now industry default for agent-tool wiring. 50+ security MCP servers already published (Nmap, Burp, Nuclei, Shodan, BloodHound, Semgrep, Trivy). PortSwigger ships an official Burp MCP server. This is where you should spend your integration effort.
- **Sandbox:** Docker is fine for tools; gVisor or Firecracker if you're running generated exploit code. Network egress should be opt-in and logged.
- **Vector store:** Qdrant or pgvector for docs; **Neo4j** for the CVE/CWE graph.
- **Memory:** Redis for short-term; Postgres for long-term findings.

---

## 3. The MCP question — and its risks

MCP is the right primitive, but you must read the safety audits (arXiv:2504.03767 "MCP Safety Audit", arXiv:2602.01129 "SMCP: Secure Model Context Protocol"). Real risks:
- **Tool poisoning** — attacker-controlled tool description or response smuggles instructions.
- **Privilege escalation** — agent chains tool calls to exceed intended scope.
- **Prompt injection via tool output** — third-party data (a fetched page, a CVE description) carries instructions.

Mitigations to bake in from day one:
- Schema-validated tool I/O (no free-form strings into shell).
- Human-in-the-loop on any tool that mutates state outside the sandbox.
- Per-tool allow-listing with least-privilege scopes.
- Sanitize tool outputs before re-feeding to the planner.
- Audit log of every tool call with diff-able inputs.

---

## 4. Knowledge grounding — what to feed the agent

The literature is clear that an agent without curated security knowledge underperforms one with even a simple CVE lookup. Concrete data sources:
- **NVD / CVE JSON feeds** (live) — your canonical "is this vuln real and what's its score" source.
- **CWE catalog** — weakness taxonomy; pairs with CVE for pattern detection.
- **CAPEC** — attack patterns; what to *try* given a CWE.
- **ATT&CK** — adversary TTPs; essential for blue-team and threat-modeling mode.
- **EPSS** — exploitation probability; helps prioritize.
- **ExploitDB / GitHub Advisory / OSV** — known PoCs and patches.
- **Vendor advisories, project READMEs, source code** (per-project RAG).

Build a knowledge graph with **CVE –[exploits]→ CWE –[mitigated_by]→ CAPEC –[used_in]→ ATT&CK technique** edges. CyKG-RAG (CEUR-WS Vol-3950) and CVE-KGRAG show measurable gains over flat text RAG.

---

## 5. Safety of the agent itself

Read **OWASP Top 10 for LLM Applications 2025** (released Nov '24) and **OWASP Top 10 for Agentic Applications 2026** (released Dec '25). The agentic list is what you specifically care about:
1. Memory poisoning
2. Tool misuse / excessive agency
3. Privilege compromise
4. Resource exhaustion (cost DoS)
5. Cascading prompt injection across tools
6. Supply chain (third-party tools / prompts)
7. Identity / impersonation
8. Goal hijack
9. Inadequate sandboxing
10. Unexpected code execution (RCE via generated shell)

Also relevant: the emerging **OWASP Agentic Skills Top 10 (AST10)** — treats skill/prompt bundles as the new supply-chain unit.

Design your system around these from the start. The "architectural property = reliability" thesis (arXiv:2512.09458) is the right frame: don't bolt safety on at the end.

---

## 6. Phased build roadmap

Here's the path I'd actually take, ordered by value-per-effort:

### Phase 1 — Codebase analysis agent (2–4 weeks)
- Single LangGraph workflow: clone repo → run **Semgrep + CodeQL via MCP** → LLM triages findings → correlates to CWE → produces a report with evidence.
- Hybrid RAG over the repo (vector) + CVE/CWE knowledge (graph).
- Use SEC-bench's gold-patch evaluator idea for self-checking.
- **Why first:** This is the highest-signal use case (you have many codebases, the tools are stable, MCPs exist), and it's where the literature says even simple agents add the most value.

### Phase 2 — Web app pentest agent (4–8 weeks)
- Add Burp + Nmap + Nuclei MCPs.
- HPTSA-style: planner spawns specialist sub-agents per vuln class (SQLi, XSS, auth).
- Incalmo-style abstraction: typed primitives, not raw shell.
- Sandbox all active probing; cap target scope.
- **Why second:** This is where the offensive-agent literature is mature. PentestGPT v2 and HPTSA give you reusable patterns.

### Phase 3 — Multi-host / enterprise agent (optional, 8+ weeks)
- Add BloodHound, CrackMapExec-style primitives.
- Incalmo's high-level attack abstraction for lateral movement.
- Only if you have real enterprise engagements.

### Phase 4 — Blue-team / SecOps agent (parallel track)
- SIEM/SOAR integrations via MCP (Elastic, Splunk, Tines, Torq).
- Alert triage → IOC enrichment → response playbook execution.
- Strong HITL; this is where false positives hurt most.

### Phase 5 — Continuous benchmarking
- Stand up SEC-bench and CVE-Bench locally.
- Track agent success rate over time as you swap models / prompts / tools.
- This is your regression suite.

---

## 7. Things I'd specifically NOT do

- **Don't start with autonomous exploitation.** The legal and safety surface is enormous; even researchers gate it. Always require explicit human approval for active testing beyond recon.
- **Don't skip the verifier.** Every paper that benchmarks honestly shows agents claim success they didn't achieve. A second-model check or rule-based check on every finding is mandatory.
- **Don't let the LLM call shells directly.** Use typed tool primitives. (Incalmo's whole point.)
- **Don't trust MCP servers blindly.** The MCP Safety Audit found real exploits via tool poisoning. Sandbox and schema-validate.
- **Don't try to replace your analysts.** The benchmarks agree: ~10–35% success means human-in-the-loop is the product, not an afterthought.

---

## 8. TL;DR for a builder

If you only take three things from this report:

1. **Build it as Plan-then-Execute + Verifier, with HPTSA-style specialist workers, talking to tools via MCP, grounded in a CVE/CWE knowledge graph.** This is the convergent pattern of 2025–2026.
2. **Sandbox everything, schema-validate every tool call, and put a human in the loop on any mutating action.** MCP safety is a real and unsolved problem.
3. **Use SEC-bench + CVE-Bench as your regression suite from day one.** Without honest measurement you'll ship something that feels smart but isn't.

Want me to drill into any one of these — e.g., sketch the LangGraph graph for Phase 1, pick the MCP servers, design the knowledge graph schema, or stand up SEC-bench locally? Happy to go deeper.

---

## Key references (all verified URLs)

- PentestGPT — https://arxiv.org/abs/2308.06782 (USENIX Sec '24)
- HPTSA — https://arxiv.org/abs/2406.01637 / https://aclanthology.org/2026.eacl-long.2.pdf
- Incalmo — https://arxiv.org/abs/2501.16466
- PentestAgent — https://arxiv.org/abs/2411.05185
- SEC-bench — https://arxiv.org/abs/2506.11791 (NeurIPS '25)
- CVE-Bench — https://arxiv.org/abs/2503.17332 (ICML '25)
- PrimeVul — https://arxiv.org/abs/2410.16277 (ICSE '25)
- CRAKEN — https://openreview.net/pdf?id=FnwU7ogRzv
- Plan-then-Execute security guide — https://arxiv.org/abs/2509.08646
- Architectures for Agentic AI — https://arxiv.org/abs/2512.09458
- CyKG-RAG — https://ceur-ws.org/Vol-3950/paper1.pdf
- CVE-KGRAG — https://github.com/Yuning-J/CVE-KGRAG
- MCP Safety Audit — https://arxiv.org/abs/2504.03767
- SMCP — https://arxiv.org/abs/2602.01129
- OWASP Top 10 for LLM Apps 2025 — https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP Top 10 for Agentic Applications 2026 — https://genai.owasp.org/
- AWS Security Agent (multi-agent pentest) — https://aws.amazon.com/blogs/security/inside-aws-security-agent-a-multi-agent-architecture-for-automated-penetration-testing/
- PentestGPT code — https://github.com/GreyDGL/PentestGPT
- 50+ security MCP servers — https://github.com/hackersatyamrastogi/pentesting-cyber-mcp
- PortSwigger Burp MCP — https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc
- Semgrep MCP — https://semgrep.dev/blog/2025/giving-appsec-a-seat-at-the-vibe-coding-table
