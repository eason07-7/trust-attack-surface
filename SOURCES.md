# 來源清單

> ⭐ = 一手來源(官方 advisory、原始研究、廠商技術報告、當事人原文);其餘為二手報導/分析。所有日期 `YYYY-MM-DD`。

## 框架與標準
- ⭐ SLSA Threat Model — https://slsa.dev/spec/v1.1-rc1/threats
- ⭐ CNCF TAG-Security, Catalog of Supply Chain Compromises — https://tag-security.cncf.io/community/catalog/compromises/compromise-definitions/
- ⭐ MITRE ATT&CK T1195 — https://attack.mitre.org/techniques/T1195/ ；T1547 — https://attack.mitre.org/techniques/T1547/
- ⭐ ENISA, Threat Landscape for Supply Chain Attacks (2021) — https://www.enisa.europa.eu/publications/threat-landscape-for-supply-chain-attacks
- ⭐ NIST, EO 14028 / SSDF / C-SCRM — https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity

## 案例:XZ Utils (CVE-2024-3094)
- ⭐ Andres Freund 原始揭露(oss-security, 2024-03-29) — https://www.openwall.com/lists/oss-security/2024/03/29/4
- ⭐ Russ Cox 時間線 — https://research.swtch.com/xz-timeline
- ⭐ Kaspersky Securelist 社交工程分析 — https://securelist.com/xz-backdoor-story-part-2-social-engineering/112476/
- ⭐ rheaeve 時區分析 — https://rheaeve.substack.com/p/xz-backdoor-times-damned-times-and
- Wikipedia — https://en.wikipedia.org/wiki/XZ_Utils_backdoor ；JFrog ；Datadog Security Labs

## 案例:npm chalk/debug + Axios
- ⭐ axios 官方 post-mortem (#10636) — https://github.com/axios/axios/issues/10636
- ⭐ Aikido(即時偵測時間軸) — https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised
- ⭐ Security Alliance / SEAL(鏈上追蹤「5 美分」) — https://www.securityalliance.org/news/2025-09-npm-supply-chain
- ⭐ Wiz — https://www.wiz.io/blog/widespread-npm-supply-chain-attack-breaking-down-impact-scope-across-debug-chalk
- ⭐ Google GTIG(Axios 歸因/60 萬下載) — https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package
- ⭐ Microsoft(Axios 歸因 Sapphire Sleet) — https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/
- ⭐ CISA Alert(Axios, 2026-04-20) — https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager

## 案例:GitHub 假倉庫 / SEO 投毒
- ⭐ 原作者一手復盤:X @ProbiusOfficial — https://x.com/ProbiusOfficial ；轉載討論 — https://linux.do/t/topic/2237885
- ⭐ 真品專案 — https://github.com/Hmbown/DeepSeek-TUI
- ⭐ CMU/NCSU/Socket, StarScout「假 star」研究(ICSE 2026) — https://arxiv.org/abs/2412.13459
- ⭐ Check Point, Stargazers Ghost Network — https://research.checkpoint.com/2024/stargazers-ghost-network/
- ⭐ Apiiro, GitHub repo confusion(10 萬+ 惡意 repo) — https://apiiro.com/blog/malicious-code-campaign-github-repo-confusion-attack/
- 同型情資:EtherRAT(gbhackers)、GPUGate(Arctic Wolf)、Trend Micro 假 GitHub repo

## 案例:其他
- ⭐ SolarWinds:CrowdStrike SUNSPOT — https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/ ；MITRE C0024 — https://attack.mitre.org/campaigns/C0024/ ；Krebs — https://krebsonsecurity.com/2021/01/solarwinds-what-hit-us-could-hit-others/
- ⭐ 依賴混淆:Alex Birsan 原文 — https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- ⭐ event-stream:npm 官方 — https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident ；Snyk post-mortem
- ⭐ Codecov 官方 post-mortem — https://about.codecov.io/apr-2021-post-mortem/
- ⭐ 3CX:Mandiant — https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise ；Krebs
- ⭐ Shai-Hulud:CISA 警報 — https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem ；Datadog 2.0 分析 — https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/ ；Shai-Hulud 帶有效 provenance(Mend / VentureBeat 報導)

## 防禦:出處/完整性層
- ⭐ Sigstore — https://docs.sigstore.dev/about/security/ ；npm provenance — https://docs.npmjs.com/generating-provenance-statements/
- ⭐ npm Trusted Publishing GA — https://github.blog/changelog/2025-07-31-npm-trusted-publishing-with-oidc-is-generally-available/
- ⭐ npm staged publishing & install controls — https://github.blog/changelog/2026-05-22-staged-publishing-and-new-install-time-controls-for-npm/
- ⭐ Reproducible Builds — https://reproducible-builds.org/ ；diffoscope — https://github.com/brettcs/diffoscope ；Google OSS Rebuild — https://blog.google/security/introducing-oss-rebuild-open-source/

## 防禦:掃描/行為/聲譽層
- ⭐ OSV — https://osv.dev/ ；OpenSSF Scorecard — https://scorecard.dev/ ；deps.dev — https://deps.dev/
- ⭐ Socket Firewall — https://socket.dev/blog/introducing-socket-firewall ；https://github.com/SocketDev/sfw-free
- ⭐ Aikido Safe Chain — https://www.aikido.dev/blog/introducing-safe-chain ；https://github.com/AikidoSec/safe-chain
- ⭐ OpenSSF Package Analysis — https://github.com/ossf/package-analysis
- ⭐ StarScout 開源 — https://github.com/hehao98/starscout ；realstars — https://github.com/mercurialsolo/realstars

## 防禦:隔離/執行期
- ⭐ gVisor — https://gvisor.dev/ ；Firecracker — https://firecracker-microvm.github.io/ ；bubblewrap — https://github.com/containers/bubblewrap ；nsjail — https://github.com/google/nsjail
- ⭐ Deno security — https://docs.deno.com/runtime/fundamentals/security/ ；Wasmtime — https://docs.wasmtime.dev/security.html
- ⭐ Falco — https://falco.org/ ；Tetragon — https://github.com/cilium/tetragon ；LavaMoat — https://github.com/LavaMoat/LavaMoat

## 防禦:事件響應/憑證
- ⭐ CISA AA20-245a, Technical Approaches to Uncovering and Remediating Malicious Activity — https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-245a
- ⭐ PersistenceSniper — https://github.com/last-byte/PersistenceSniper ；Volatility — https://github.com/volatilityfoundation/volatility3
- Chrome DBSC — https://scotthelme.ghost.io/device-bound-session-credentials-making-stolen-cookies-useless/

## 研究/趨勢
- ⭐ Beneath the Mask(maintainer 異常偵測) — https://arxiv.org/abs/2508.13453
- ⭐ Social Proof is in the Pudding(同儕審查) — https://tsjournal.org/index.php/jots/article/view/286 ；arXiv — https://arxiv.org/abs/2603.07919
- ⭐ Sonatype State of the Software Supply Chain 2024 / 2026 — https://www.sonatype.com/state-of-the-software-supply-chain/2026/open-source-malware

---

### 引用注意
- 數字若來源分歧(如 chalk/debug 實得金額、套件下載基數、Shai-Hulud 套件數),本倉庫採一手來源並標明分歧。
- 部分 arXiv preprint 與 2025–2026 事件報導,引用前請再核一手全文。
