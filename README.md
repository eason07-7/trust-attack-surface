# Trust Is the Attack Surface

> **供應鏈攻擊不是攻破你的密碼學或漏洞,而是攻破「信任的轉移鏈」。**
> *They don't break your crypto — they break your trust.*

一份關於**軟體供應鏈攻擊**的客觀調查:標誌性案例的事實重建、攻擊全貌與分類、以及橫跨「安裝前 / 安裝時 / 安裝後」的防禦現況與開放問題。**重一手來源、重時間戳、明確區分「已證實 / 推測 / 未證實」。** 完整引用見 [SOURCES.md](SOURCES.md)。

供應鏈攻擊的可怕之處在於:你什麼都沒做錯——你用了正版、簽章過、來自官方來源的東西——但你信任的上游被下了毒,毒順著「鏈」流進你的系統。最有力的一個事實:2025 年的 **Shai-Hulud** npm 蠕蟲,惡意版本**全帶有效的 SLSA Build Level 3 provenance 簽章**——證明完整性防線(簽章 / SBOM / provenance / 2FA)可以**全數通過,套件仍然是毒的**。

**三句話帶走:**
1. **攻擊本質**:漏洞利用攻「弱點」;供應鏈攻擊攻「信任」——後者更難防,因為防線本身(自動更新、官方 registry、CI)就是傳播管道。
2. **最危險的盲區**:「**合法但惡意**」——當惡意由被信任的合法主體、經合法管道、以合法形式發出時,完整性控制全數通過卻無法阻擋。
3. **防治規律**:成本與可靠性沿安裝生命週期單調惡化——「安裝前」最便宜且可阻斷,「安裝後」最貴且無法保證除淨。

---

## 目錄

- [一、什麼是供應鏈攻擊](#一什麼是供應鏈攻擊)
- [二、案例研究](#二案例研究)
- [三、防禦現況與開放問題](#三防禦現況與開放問題)
- [來源](#來源)
- [聲明與授權](#聲明與授權)

---

# 一、什麼是供應鏈攻擊

## 1.1 精確定義

**白話**:你信任的「上游」(寫程式的人、你用的開源套件、你的 build 機器、你下載軟體的地方)被動了手腳,毒順著這條「鏈」一路流進你的系統——你什麼都沒做錯,只是「用了該用的東西」。

權威定義:
- **CNCF(TAG Security)**(最精煉):「軟體供應鏈是撰寫、測試、封裝、散布軟體給終端消費者的一連串步驟;**當生產軟體的『材料』或『流程』本身被破壞、導致下游消費者受害,即為軟體供應鏈攻擊。**」
- **CISA**:威脅行為者滲透軟體供應商網路,在軟體送交客戶**之前**植入惡意碼;三大典型手法 = **劫持更新、破壞程式碼簽章、汙染開源程式碼**。
- **ENISA**:供應鏈攻擊「至少結合兩次攻擊——先攻供應商,再以供應商為跳板攻其客戶」;**66% 鎖定供應商程式碼、62% 的客戶受害是因為信任供應商**。
- **NIST**:以 **C-SCRM(SP 800-161)** 框定,涵蓋設計→開發→交付→整合→運維→汰除全生命週期。

**與「一般漏洞利用」的本質差異:**

| | 一般漏洞利用 | 供應鏈攻擊 |
|---|---|---|
| 攻擊對象 | 你軟體裡的 **bug/弱點** | 你對上游的 **信任關係** |
| 你有沒有做錯 | 通常是你沒修補/設定錯 | 你照規矩用了「正版、簽章過、官方來源」 |
| 偵測難度 | 有 CVE、有 patch、掃得到 | 碼「看起來合法」、簽章有效、來源可信,**繞過傳統防線** |
| 影響範圍 | 單一系統 | 一次汙染,**所有下游全中**(blast radius 巨大) |

> **核心一句**:漏洞利用攻的是「弱點」;供應鏈攻擊攻的是「信任」。

## 1.2 完整的軟體供應鏈地圖(對應 SLSA 模型)

```
開發者 ─①─> 原始碼/版控 ─②─> 相依套件 ─③─> Build/CI ─④─> 簽章/封裝 ─⑤─> Registry/CDN ─⑥─> 安裝 ─⑦─> 執行期
  (人)        (Git)         (deps)       (build)      (sign/pkg)     (distribute)   (install) (runtime)
```

| 環節 | 可能被攻擊的點 | SLSA 威脅點 |
|---|---|---|
| ① 開發者/帳號 | 帳號劫持、開發機被植 infostealer、社工長線滲透成維護者 | 前置 |
| ② 原始碼/版控 | 未授權變更、攻破 repo 注入惡意 commit | A 提交未授權變更 / B 攻破源碼庫 |
| ③ 相依套件 | 引入惡意依賴、先無害後更新成惡意、依賴混淆/typosquat | E 使用被汙染相依 |
| ④ Build/CI | 用「不符版控」的源碼建置、build 環境被植 implant | C 從被改源碼建置 / D 攻破建置流程 |
| ⑤ 簽章/封裝 | 簽章金鑰竊取、產物建置後上傳前被掉包 | F 上傳被竄改封裝 |
| ⑥ 散布 | 攻破套件庫、鏡像/CDN 汙染、SEO 假專案誘導下載 | G 攻破套件庫 |
| ⑦ 安裝/執行期 | 被騙裝惡意/仿冒套件、install script 觸發、執行期下載 payload | H 使用被汙染套件 |

> SLSA 的 **Build track** 最成熟(L1–L3),Source/Dependency track 仍在發展。

## 1.3 攻擊面分類學

| 攻擊手法 | 一句定義 | 知名實例 |
|---|---|---|
| 依賴混淆 (Dependency Confusion) | 在公共 registry 註冊與企業私有套件同名但更高版本,騙解析器抓公共惡意版 | Alex Birsan 2021 |
| Typosquatting/搶註 | 用拼錯/近似名上架惡意套件等人打錯 | PyPI 每月下架數百 |
| Slopsquatting (AI 幻覺搶註) | 搶註 LLM「幻想」出來、實不存在的套件名 | 新興詞,定義浮動 |
| 惡意維護者/長線社工 | 數月~數年取得維護權再植後門 | XZ Utils |
| 帳號劫持 | 竊取維護者憑證/token 直接發惡意版 | chalk/debug |
| Build/CI 污染 | 攻破 CI 在建置時注入惡意 | SolarWinds |
| 簽章金鑰竊取 | 偷私鑰讓惡意產物帶合法簽章 | Codecov |
| 相依套件投毒 | 把惡意藏進廣用 library、先無害後更新 | event-stream |
| 上游 tarball ≠ 源碼 | 散布產物與 Git 源碼不符,惡意只在 tarball | XZ 後門 |
| 鏡像/CDN 污染 | 攻破鏡像/CDN 讓下載者拿被掉包檔 | SLSA 威脅 G |
| IDE/外掛市集投毒 | 在 VS Code/Open VSX 上架或劫持惡意擴充 | GlassWorm (2025–26) |
| SEO/搜尋投毒散布假專案 | 用 SEO/假 repo 把惡意工具推上搜尋頂端誘下載 | 見 [2.3](#23-github-假倉庫木馬--seo搜尋投毒) |

> 分類學無單一官方版本(ENISA / SLSA / CNCF / Sonatype 各有切法),本表為綜合整理。

## 1.4 歷史與演進

| 時期 | 代表事件 | 特徵 |
|---|---|---|
| 早期 (2013–2017) | Target HVAC 跳板、CCleaner | 把第三方廠商當跳板;偶發、手工 |
| SolarWinds 時代 (2020–2021) | SolarWinds Orion、Codecov | 國家級、攻 build/簽章、潛伏期長——**分水嶺** |
| 開源大規模投毒 (2021–2024) | 依賴混淆、event-stream、XZ | 轉向攻「開源公地」與維護者;手法工業化 |
| AI 工具誘餌時代 (2025–) | chalk/debug、Shai-Hulud 蠕蟲、GlassWorm、slopsquatting | 自動化、自我繁殖、跨生態;以 AI 工具/開發者為餌;時間軸從「年」壓縮到「天」 |

**為何近年爆增**:① 開源依賴爆炸(blast radius 放大)② 自動更新 + 快速發布(惡意搭正常更新直送)③ CI/CD 普及(靠近敏感資料與生產權限)④ 攻擊 ROI 極高(攻一上游 = 拿下成千上萬下游)⑤ AI 加速(生成碼拉入開源、催生 slopsquatting)。數據:ENISA 估 2021 為 2020 的 4 倍;Sonatype 2026 報告累計已知惡意套件突破 **123 萬**。

## 1.5 關鍵術語表

| 術語 | 白話 |
|---|---|
| SBOM | 軟體版「成分標示」,列出用了哪些元件/版本/來源,出事能快速查影響 |
| SLSA | 供應鏈安全分級框架,把「可不可信」變成 L1–L3 可驗證等級 |
| Provenance / Attestation | 「這產物用哪份源碼、在哪台機器、何時建出」的可驗證紀錄與簽章 |
| SCA | 掃描你用了哪些第三方元件、有無已知漏洞/惡意的工具 |
| Dependency Confusion | 用同名更高版本公共套件騙系統抓公共惡意版 |
| 0-day malware | 才上架、還沒被任何掃描器標記的全新惡意套件 |
| Blast Radius | 一個被汙染元件爆掉時連帶受害的範圍 |

## 1.6 為什麼難防(本質)

供應鏈攻擊難防的根本在於它**攻擊「信任」而非「漏洞」**:惡意碼藏在你本該信任、且有有效簽章與官方來源的元件裡,沿著你的防線(自動更新、官方 registry、CI)當高速公路傳播,**繞過以「找弱點、打補丁」為核心的傳統防禦**;再加上 **blast radius 極大**(一次汙染命中成千上萬下游)與嚴重**資訊不對稱**(攻方只要在某維護者/某 build 環節/某 tarball 找到一個破口,守方卻得對看不全的整條鏈負責)。**守方要全對,攻方只要一次得手。**

## 1.7 攻擊本質:把信任變成武器

不同案例表層手法迥異(build 污染 / 帳號劫持 / 搜尋投毒),但**標的都是「信任」**,且都把人類與系統的「信任捷思(heuristics)」當攻擊面:

1. **「知名/高 star/高下載 = 可信」的權威捷思**:正因太可信太基礎,沒人逐版審查,攻擊者寄生於「大到不會被懷疑」。
2. **利用維護者社群的善意、過勞與無償性**:把關鍵基礎設施交給少數志願者——攻擊的是**治理結構**,不是程式碼。
3. **利用自動更新與語意化版本(`^`/`~`)的隱性信任**:拿下發布權即全網自動分發,惡意版本 2 小時就能觸及 1/10 雲環境。
4. **利用「搜尋排名 = 權威」「GitHub = 可信」的認知**:偽造這些信任憑證,受害者甚至是資安研究者與系統管理員。
5. **共通結構 = 合法外殼 + 延遲/條件觸發 + 信任路徑寄生**:讓「惡意」與「被信任的合法載體」在時間或空間上分離,使單點檢查(看 git/帳號/registry/搜尋結果)都「看起來正常」。

> **一句話**:供應鏈攻擊不是攻破密碼學或漏洞,而是**攻破信任的轉移鏈**——攻擊者只需在「我信任 X、X 信任 Y」插入自己,整條鏈的完整性反而幫他可信地分發惡意產物。

**權威框架對照**:CNCF《Catalog of Supply Chain Compromises》、MITRE ATT&CK **T1195**、ENISA Threat Landscape(62% 利用信任)、SLSA Threat Model(A–I)。值得注意:SEO/假 repo 型大致落在 SLSA 模型的「Usage 之外」——SLSA 假設你**已選對 repo**,對「怎麼找到 repo」這段近乎不設防。

---

# 二、案例研究

三個深度案例(各代表一種打法)+ 跨生態的廣度案例。每個案例都附**事實校正**,點出中文社群轉述時常見的失真。所有歸因標注確定性。

## 2.1 XZ Utils 後門(CVE-2024-3094)— 長線社工

**概述**:2024-03 揭露。化名 **"Jia Tan"(GitHub: JiaT75)** 透過約兩年社交工程,逐步取得壓縮函式庫 **xz / liblzma** 共同維護者權限,在 5.6.0 / 5.6.1 植入後門:透過部分發行版 systemd 補丁讓 liblzma 被 sshd 載入,hook RSA 簽章驗證,持有特定 **Ed448 私鑰**者可在認證前(pre-auth)遠端執行任意程式碼。CVSS **10.0**。

**精確時間軸:**
| 日期 | 事件 |
|---|---|
| 2021-01-26 | GitHub 帳號 JiaT75 建立 |
| 2022-02-07 | Lasse Collin **合併 Jia Tan 首個 commit** |
| 2022-04~06 | 假帳號 "Jigar Kumar" 連環施壓要求換維護者 |
| 2022-06-21 | 假帳號 "Dennis Ens" 施壓交棒 |
| 2022-11-30 | **正式取得 co-maintainer** |
| 2023-03-18 | 首次以維護者身分發版 v5.4.2 |
| 2024-02-24 | **發布 5.6.0**,tarball 含惡意 `build-to-host.m4`(不在 Git) |
| 2024-03-29 | **Andres Freund 在 oss-security 公開揭露** |
| 2024-05-29 | 修補版 5.6.2 |

**技術機制**:① 惡意二進位藏在「損壞的測試壓縮檔」,源碼倉庫看似乾淨;② 惡意 `build-to-host.m4` **只在發布 tarball、不在 Git**,`./configure` 時解出腳本注入編譯產物;③ 濫用 GNU IFUNC,因 systemd 補丁讓 sshd 連結 liblzma,hook `RSA_public_decrypt` 達成 pre-auth RCE。觸發條件:x86-64 + glibc + GCC + deb/rpm 打包。

**發現經過**:微軟工程師 Andres Freund 做 PostgreSQL benchmark 注意到 ssh 登入時間 **0.299s→0.807s**、Valgrind 報錯指向 liblzma,追到後門。

**影響**:主要進**滾動/開發版**(Fedora Rawhide/40 beta、Debian unstable/testing、openSUSE Tumbleweed、Kali、Arch);**Debian stable、RHEL、SUSE Enterprise、已發布 Ubuntu 全未受影響**。

**⚠️ 事實校正:**
- 「演戲 700 天」——須註明起點:首個被合併 commit→投毒約 **746 天**;首封補丁算 ~847 天;帳號建立算 ~1123 天。
- 「差點毒翻全球 Linux」——「**差點**」對、「已毒翻」錯;只進開發/測試版,因及早發現未大規模部署。
- 「Jia Tan 是中國黑客」——**不準確、可能被刻意誤導**;時區/工作時段/不可能行程證據指向 commit 偽裝成 UTC+8,真實活動更可能在東歐/中東;**具體歸屬無定論**。
- 「sshd 本身被加後門」——上游 OpenSSH 乾淨;是發行版 systemd 補丁讓 sshd 間接連結 liblzma。
- 「GitHub 看得到後門碼」——錯;惡意觸發腳本只在 release tarball。

## 2.2 npm 投毒:chalk/debug(2025-09)+ Axios(2026-03)— 帳號劫持

> ⚠️ 中文社群常把「**Axios 被劫持 3 小時、被上億下載**」當單一事件——這是**兩起事件混淆嫁接**:「3 小時」屬 Axios;「上億下載 + 竊加密貨幣」屬 chalk/debug。

**chalk/debug(2025-09-08)— 「巨量下載 + crypto」主體**
- 維護者 Josh Junon(`qix`)收到偽冒 npm 的「2FA 重設」釣魚信(來自攻擊前 3 天註冊的 `npmjs.help`),即時被收走帳密 + TOTP。
- 18 個基礎套件(chalk/debug/ansi-styles…)合計**每週 ~26 億次下載**;payload 為純瀏覽器端 crypto drainer(在簽章前竄改錢包收款地址)。
- 時間窗(UTC):`13:16` 上架 → `~15:20` 示警 → 約 **2 小時**回退。
- **實際得手:極小**——鏈上追蹤實得約 **5 美分 ETH + ~$20 迷因幣**(報告標題〈Oops, No Victims: The Largest Supply Chain Attack Stole 5 Cents〉)。

**Axios(2026-03-31)— 「3 小時」出處**
- 維護者帳號被奪;歸因北韓 nexus(Google GTIG = UNC1069;微軟 = Sapphire Sleet)。
- 惡意版 axios 1.14.1 / 0.30.4 注入假依賴 `plain-crypto-js`,post-install 下載跨平台 RAT(WAVESHAPER.V2)——**非竊幣、是間諜 RAT**。
- 時間窗:`00:21` 發布 → `03:15` 移除,約 **3 小時**;惡意版本窗口內實際被拉取約 **60 萬次**;axios 主線 >1 億次/週。

**⚠️ 事實校正:**
1. 「上億/數十億下載」= **套件下載基數**,不是惡意版本被拉取次數(Axios 實際 ~60 萬次)。**曝險巨大 ≠ 實損巨大**。
2. 「3 小時」屬 Axios;「crypto drainer + 上億下載」屬 chalk/debug,不可混。
3. 惡意碼性質不同:chalk/debug 是**前端竊幣**;Axios 是**安裝期 RAT**。

## 2.3 GitHub 假倉庫木馬 — SEO/搜尋投毒

> 本案核心事實來自資安研究者 **探姬(@ProbiusOfficial,Hello-CTF 作者)本人公開的事故復盤**。原文出處:[X @ProbiusOfficial](https://x.com/ProbiusOfficial)(轉載討論見 [linux.do topic 2237885](https://linux.do/t/topic/2237885))。本節為摘要與技術整理,完整細節請見原作者一手復盤。

**概述**:研究者比賽前夕想試用爆紅終端 AI 工具,誤下載一個**惡意 fork**:約 **300+ star、上過 GitHub Trending、Bing 搜「DeepSeek-TUI」排第一**。原專案 `Hmbown/DeepSeek-TUI` 是安全的;惡意 fork 僅比原版大約 **2MB**,這 2MB 即一整套多階段 Rust 木馬。執行後其 X 帳號被盜。

**二次傳播(關鍵教訓)**:原惡意倉庫後被刪,但其本體**被多個知名專案收錄**(如一個 13k star 的倉庫包含它)、被 AI 推薦、部分 fork 保留帶毒 Release——即原倉庫消失仍持續擴散。

**帳號被盜時間線**:Day 0 下載執行;Day 1 Google 寄信提示「帳號信箱已被修改」未注意(X 有 24–48h 改信箱窗口期,錯過了);Day 2 帳號被強制下線;後續申訴找回。

**技術解剖(一手 IDA 分析)**:模組化多階段木馬家族,**至少 5 個同源 Rust 樣本**,共享 `memexec` 記憶體載入;具備註冊表 Run 鍵 / 計畫任務 `schtasks /ONLOGON /RL HIGHEST` / Winlogon Userinit / Startup .lnk 多重持久化、7 項反沙箱、RC4 解密(密鑰綁 PID)、無檔案記憶體執行;C2 走 Pastebin / Snippet.host raw。瀏覽器密碼/cookie 在此階段易被竊。

> **歸因註記**:技術細節為原作者一手分析;本案屬同期一波「假冒爆紅 AI 工具」GitHub 投毒潮,但不武斷歸入任何具名行動。

**攻擊手法本質**:惡意 repo 爬上搜尋/Trending 第一的手法——**刷 star/fork(機器人/Ghost 帳號)、頻繁無意義 commit 偽造「最近更新」、蹭熱門關鍵字 + 黑帽 SEO、付費刷星**。佐證規模:CMU/Socket「StarScout」研究估約 **600 萬疑似假 star**;Check Point「Stargazers Ghost Network」記錄 3,000+ Ghost 帳號的 Distribution-as-a-Service;Apiiro 2024-02 偵測 10 萬+ 惡意 repo。

**⚠️ 事實校正:**
- 「DeepSeek-TUI 是木馬」——錯;原專案安全,中毒的是**惡意 fork**。
- 「連大佬都中招 = 工具有問題」——因果倒置;中招源於**搜尋排名/star 被操控** + 在熱門期主動試用,非工具缺陷。
- 「star 數/Trending = 可信」——正是被利用的盲點(研究顯示 50 star 的 repo 已有約 15% 涉刷星)。

## 2.4 其他代表性案例(廣度)

| 案例 | 年份 | 生態/層面 | 攻擊類型 | 歸因確定性 |
|---|---|---|---|---|
| SolarWinds SUNBURST | 2020 | 閉源企業 build | build-time 注入 | **定論**(APT29/SVR) |
| Dependency Confusion | 2021 | 跨 registry(原型) | 命名空間混淆 | 白帽研究 |
| event-stream | 2018 | npm | 維護權交棒接管 | 無定論 |
| Codecov | 2021 | CI/CD 工具 | 工具污染竊 secrets | 無定論 |
| 3CX | 2023 | 閉源桌面 app | 雙重級聯供應鏈 | 高共識(Lazarus) |
| ua-parser-js | 2021 | npm | 帳號劫持 | 無定論 |
| ctx (PyPI) | 2022 | PyPI | 過期網域接管 ATO | 無定論 |
| Shai-Hulud | 2025 | npm | 自我複製蠕蟲 | 無定論 |

**SolarWinds / SUNBURST(2020)— 企業 build-system 污染標誌案**:攻擊者植入 **SUNSPOT** 常駐 build 伺服器,在 Visual Studio 編譯 Orion 時 **just-in-time** 把後門換進源檔、編完**立即還原**,產物以 SolarWinds **合法簽章**簽署。約 **18,000** 組織安裝受污染更新,僅對 **<100** 高價值目標啟動後門。2021-04 美英歸因俄 SVR(APT29)。

**Dependency Confusion(Alex Birsan,2021)— 依賴混淆鼻祖**:蒐集企業內部私有套件名,到公共 registry 以極高版本號搶註同名,套件管理器自動優先選最高版本 → 拉到攻擊者套件。在 **35+** 公司取得程式碼執行,獲 **>$13 萬** bug bounty。白帽研究。

**event-stream(2018)— 維護者交棒接管早期經典**:原作者把發布權交給主動表示願幫忙的 `right9ctrl`,後者植入只在 Copay 比特幣錢包 build 時觸發、竊取私鑰的 payload。與 XZ「長期博取信任後接棒」直接呼應。

**Codecov(2021)— CI 工具污染竊 secrets**:攻擊者從 Codecov 的 Docker image 抽出憑證,竄改廣用的 bash uploader,在客戶 CI 執行時擷取**全部環境變數**(AWS 金鑰、token)外送。約 23,000+ 客戶潛在受影響。

**3CX(2023)— 史上首例「雙重供應鏈攻擊」**:上游 Trading Technologies 的 X_TRADER 先被植木馬 → 3CX 員工中招 → 取得 3CX build 環境 → 污染 3CX 桌面 app → 波及下游(自稱 60 萬+ 客戶)。高共識歸因北韓 Lazarus。

**Shai-Hulud(2025)— 自我複製蠕蟲**:惡意碼在 postinstall 竊憑證、把受害者私有 GitHub repo 改 public,若找到 npm 憑證則自動把蠕蟲注入該維護者套件並重發,**自我繁殖**。2.0 波及至少 **796 套件 / 1,092 版本**、25,000+ GitHub repo。**關鍵**:2.0 惡意版本**全帶有效 SLSA L3 provenance**——完整性防線全綠燈仍中毒(見 [3.0](#30-一個決定性事實完整性--安全))。

---

# 三、防禦現況與開放問題

沿「安裝前 / 安裝時 / 安裝後」盤點防禦,標成熟度 `[已實作-產品]` / `[研究中-學術]` / `[概念討論]`,並以客觀立場列出**領域開放問題**。

## 3.0 一個決定性事實:完整性 ≠ 安全

2025 年的 **Shai-Hulud** npm 蠕蟲,惡意版本**全帶有效的 SLSA Build Level 3 provenance 簽章**。據報導(Mend 追蹤,VentureBeat):*"Every malicious version carried a valid SLSA Build Level 3 provenance attestation. The provenance was real."* 一個受害專案「紙面上設定全對:OIDC trusted publishing、簽章 provenance、每個維護者帳號都開 2FA」,照樣淪陷;攻擊用「孤兒 commit(無父歷史)」技術——真正的控制點是 **OIDC scope**,而非 provenance/2FA。

> **結論**:完整性防線(簽章 / SBOM / provenance / 2FA)可以**全數通過,套件仍然是毒的**。現有防禦多在防「**完整性**(東西沒被竄改)」,但攻擊攻的是「**真實性**(合法主體本身就是惡意)」——這是結構性盲區。

**防治規律**:成本與可靠性沿安裝生命週期單調惡化。

| 生命週期段 | 防治目標 | 可靠性 | 成本 |
|---|---|---|---|
| 安裝前 | 別讓它進來/別執行 | 高(可阻斷) | 低 |
| 安裝時/執行時 | 進來了也限制它 | 中(可規避) | 中 |
| 安裝後(已淪陷) | 清除扎根生態 | 低(打地鼠,無除淨保證) | 高(常需重灌) |

## 3.1 安裝前(Pre-execution)

**選擇/搜尋時:**
| 方法 | 成熟度 | 說明 |
|---|---|---|
| OpenSSF Scorecard / deps.dev | 已實作-產品 | 安全實踐健康度評分;衡量「實踐」非「即時意圖」(高分專案也可能惡意) |
| StarScout(CMU/NCSU/Socket) | 研究中-學術(開源) | 用 low-activity + lockstep 啟發式偵測假 star;離線批次、精緻養號可規避 |
| realstars / StarGuard | 研究中→早期原型 | 在 repo 頁顯示信任分;僅作用在 repo 頁、非搜尋結果頁 |
| typosquat 偵測(typomania/typogard/SpellBound) | 已實作+研究 | FP 與覆蓋取捨 |

**取得後、執行前(verify):**
| 方法 | 成熟度 | 說明 |
|---|---|---|
| OSS Rebuild(Google,2025-07) | 已實作-產品 | 重建熱門套件並比對「發布物有無 source 沒有的碼」;不涵蓋任意 GitHub fork |
| Reproducible Builds + diffoscope | 已實作-產品 | source↔binary 人類可讀 diff;npm/PyPI 可重現性遠低於 Debian,比對多為手動 |
| npm provenance / SLSA + slsa-verifier | 已實作-產品 | 不證明 source 本身乾淨;採用率低 |
| 沙箱「引爆」(OpenSSF Package Analysis) | 已實作-開源 | gVisor 沙箱跑套件抓惡意行為;偵測導向、可反沙箱 |

**安裝行為攔截(install-time gating):**
| 方法 | 成熟度 | 說明 |
|---|---|---|
| npm `--ignore-scripts` / `@lavamoat/allow-scripts` | 已實作-產品 | 預設停用 lifecycle script + allowlist——最實用的 postinstall 防治 |
| cooldown / `min-release-age`(npm 11.10+、Renovate) | 已實作-產品 | **僅延遲 24h 就能擋掉多數事件**(惡意版多在數小時內被下架) |
| Socket Firewall / Aikido Safe Chain | 已實作-產品(免費) | ephemeral proxy 攔 registry、裝前查情資;限制:本地 cache 命中失效、已知繞過 |
| Endor / Sonatype Repository Firewall | 已實作-產品(商用) | 坐在私有 registry 與公開 registry 間,惡意回 403 |

**管理面 / 政策**:私有 registry + allowlist、版本鎖定(lockfile / `npm ci` / pinning)、對「熱門新工具」審查 SOP、預編譯 release 不直接信任。

## 3.2 安裝時 / 執行時(Containment)

| 方法 | 成熟度 | 對 fileless | 備註 |
|---|---|---|---|
| Docker dev container | 已實作-產品 | 弱 | 共用 host kernel |
| gVisor(user-space kernel) | 已實作-產品 | 中 | syscall 密集變慢 |
| Firecracker microVM | 已實作-產品 | 強 | 獨立 kernel、拋棄式 |
| bubblewrap / nsjail | 已實作-產品 | 中 | 需手寫 seccomp/namespace |
| Deno permission model | 已實作-產品 | 弱 | 預設無 OS 存取;但 import 模組不需權限,有沙箱逃逸研究 |
| Node `--permission` | 已實作-產品(實驗) | 弱 | 官方明言**非安全沙箱** |
| WASM/WASI(Wasmtime) | 已實作-產品 | 中 | 記憶體沙箱;編譯器 bug=逃逸(CVE-2021-32629) |
| Falco(eBPF,CNCF) | 已實作-產品 | 中 | 偵測+告警 |
| Tetragon(kernel 內 eBPF) | 已實作-產品 | 中-強 | **可在 syscall 完成前 kill**,非僅告警 |
| LavaMoat SES runtime | 已實作-產品 | 弱 | 語言層限制依賴越權(凍 primordials、per-package 限網路/env) |
| Ephemeral CI + egress filter | 已實作-產品 | 中 | 用完即銷,**直接斷 persistence** |

> 沒有單一技術通吃。最佳實務分層:安裝期(allow-scripts + Socket/Aikido)→ 隔離執行(gVisor/Firecracker)→ 執行期 EDR(Tetragon/Falco)→ 環境層(ephemeral CI + egress)。對 fileless/memexec 最對症的是 kernel 層,但成熟阻擋仍偏實驗;語言層對記憶體攻擊幾乎無效。

## 3.3 安裝後 / 已淪陷(Post-compromise)

一旦多階段木馬執行,對手是**一整套互為備份、扎根系統各角落的惡意生態**:清了註冊表 Run 還有計畫任務、刪了計畫任務 Winlogon 被改、修了還有 Startup .lnk、刪了落地檔記憶體 memexec 還在跑、重啟又被 `schtasks /ONLOGON` 重建。

**持久化 → MITRE ATT&CK**:Run 鍵/Startup(T1547.001)、計畫任務(T1053.005)、Winlogon(T1547.004)、WMI 事件(T1546.003)、記憶體注入/反射載入(T1055 / T1620)。

**偵測工具與邊界:**
| 方法 | 成熟度 | 能否根除 | 限制 |
|---|---|---|---|
| Sysinternals Autoruns | 已實作-產品 | 否(列舉) | 不觸及記憶體 |
| PersistenceSniper(~60 種技術) | 已實作-產品 | 否(列舉) | 僅已知技術;對 memexec 無效 |
| Volatility(malfind/ldrmodules) | 已實作-產品 | 否(取證快照) | 只抓採證當下;來源未除則重建 |
| AMSI / ETW | 已實作-產品 | 否 | 記憶體 patch / reflection 繞過 |
| EDR / XDR | 已實作-產品 | 否(偵測+部分阻斷) | 偵測在淪陷後;unhooking/直接 syscall/reflective 繞過 |
| **重灌 / Nuke from Orbit** | 業界標準作業 | **是(高信心斷根)** | 昂貴;需先取證 |

> **memexec 偵測難點**:reflective loading 不經磁碟,多數 EDR 監控「DLL 從磁碟載入」;直接 syscall 跳過被 hook 的 ntdll。Picus 2025:54% 攻擊有被記錄,僅 **14%** 產生實際告警。**抓得到 ≠ 除得掉**——重啟後記憶體 payload 消失,但 `schtasks /ONLOGON` 下次登入又拉起,因為來源仍在。

**事件響應官方指引(CISA AA20-245a)**:① 先做**不打草驚蛇**的步驟(過早行動會逼對手藏匿或引爆勒索)② **隔離並重映像(reimage)**受感染主機才是斷根解 ③ **先發制人全憑證重置**(對手通常握多組憑證、會偽造票證;若 DC 被入侵,`krbtgt` 須重置兩次)。

**帳號/憑證後果**:被竊 **session cookie 比密碼更危險**——直接 replay 進入已驗證 session,**不需破解 MFA**(微軟 2025:80% 的 MFA 繞過涉 session token 濫用)。→ 只改密碼沒用,**必須全面撤銷 session/OAuth token**;加固用 FIDO2/passkey、Chrome DBSC(把 session 綁裝置使被竊 cookie 失效)。

> **根本限制**:已淪陷後的清除無法提供「確定除淨」的數學保證——漏一個互為備份節點(尤其「記憶體 + `/ONLOGON` 重建」組合)就回到原點。故業界退守「重灌 + 全憑證輪換」。這恰恰反證:**事前阻斷才便宜可靠。**

## 3.4 防禦缺口與領域開放問題(客觀觀察)

綜合三段防禦,以下問題目前**沒有成熟、可規模化的解法**,屬本領域公認的開放問題:

1. **「合法主體 × 惡意意圖」本身**:完整性 / 簽章 / provenance 體系**結構上無法處理**(Shai-Hulud 帶有效 SLSA L3 是鐵證)。
2. **維護者長線社工接班(XZ 模式)**:學界(如 *Beneath the Mask*, arXiv:2508.13453)明文指出「**目前不存在監控與識別跨專案異常貢獻者行為的工具**」;接班治理仍停在討論層。
3. **帳號劫持後的合法發布**:staged publishing + 2FA 只抬門檻,釣 MFA 可繞、OIDC scope 設錯仍被攻破。
4. **SEO / 搜尋投毒 + 假 repo + 認知信任層**:**最嚴重的真空**。不經受信任套件管道 → SBOM/掃描/provenance/firewall 全部無關;現有「防禦」幾乎只剩事後端點偵測(EDR)。**「開發者搜尋→點第一名→下載執行」這個認知環節幾乎零保護**。
5. **0-day 惡意套件**:known-CVE 掃描層(OSV/Dependabot/Snyk 核心)對「無 CVE 的新惡意」全 miss;行為層是唯一補位但可規避。
6. **LLM 語意審計尚不可靠**:幻覺、多階段狀態維持失敗、依賴 source repo 完整性(社工攻陷即失效)、需人類覆核——尚不能當自動化信任閘。

**一個反直覺的研究發現**:Shen, Sood & Weitzel《Social Proof is in the Pudding》(Journal of Online Trust and Safety, 2026,同儕審查)以真實田野實驗「買 star」,**找不到對下載的可辨識因果影響**。意涵:「反刷星」的主要價值在**抓惡意/詐欺信號**(惡意者仍在刷),而真正驅動「點第一名→下載」的更可能是**搜尋排名/SEO 與文件可信度**,而非 star 數本身。(單一研究、樣本為新建套件,外推須謹慎。)

---

# 來源

完整引用(一手 / 二手分層標注)見 **[SOURCES.md](SOURCES.md)**。

# 聲明與授權

- 本倉庫為**防禦性資安研究與教育用途**。內容描述攻擊的**機制與特徵**以利防禦理解,**不提供可直接濫用的攻擊武器化細節、不含惡意程式碼**。
- 所有**歸因**(國家、APT 團體、具名行動)除非有明確官方定論,一律標注為**推測**,請勿當作既成事實引用。
- 影響規模刻意區分「**曝險面 vs 實際損失**」「**下載基數 vs 實際感染數**」,避免誇大。
- 部分為 2025–2026 近期事件,引用前請以一手來源(見 [SOURCES.md](SOURCES.md))再次核實。內容若有錯誤歡迎開 issue 指正。
- 文件內容以 **CC BY 4.0** 釋出(見 [LICENSE](LICENSE))——可自由分享、改作,標明出處即可。
