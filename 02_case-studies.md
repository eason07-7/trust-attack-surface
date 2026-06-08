# 2. 案例研究

> 三個深度案例(各代表一種打法)+ 跨生態的廣度案例。每個案例都附**事實校正**,點出中文社群轉述時常見的失真。所有歸因標注確定性。

---

## 2.1 XZ Utils 後門(CVE-2024-3094)— 長線社工

**概述**:2024-03 揭露。化名 **"Jia Tan"(GitHub: JiaT75)** 透過約兩年社交工程,逐步取得壓縮函式庫 **xz / liblzma** 共同維護者權限,在 5.6.0 / 5.6.1 植入後門:透過部分發行版 systemd 補丁讓 liblzma 被 sshd 載入,hook RSA 簽章驗證,持有特定 **Ed448 私鑰**者可在認證前(pre-auth)遠端執行任意程式碼。CVSS **10.0**。

**精確時間軸**:
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

**⚠️ 事實校正**:
- 「演戲 700 天」——須註明起點:首個被合併 commit→投毒約 **746 天**;首封補丁算 ~847 天;帳號建立算 ~1123 天。
- 「差點毒翻全球 Linux」——「**差點**」對、「已毒翻」錯;只進開發/測試版,因及早發現未大規模部署。
- 「Jia Tan 是中國黑客」——**不準確、可能被刻意誤導**;時區/工作時段/不可能行程證據指向 commit 偽裝成 UTC+8,真實活動更可能在東歐/中東;**具體歸屬無定論**。
- 「sshd 本身被加後門」——上游 OpenSSH 乾淨;是發行版 systemd 補丁讓 sshd 間接連結 liblzma。
- 「GitHub 看得到後門碼」——錯;惡意觸發腳本只在 release tarball。

---

## 2.2 npm 投毒:chalk/debug(2025-09)+ Axios(2026-03)— 帳號劫持

> ⚠️ 中文社群常把「**Axios 被劫持 3 小時、被上億下載**」當單一事件——這是**兩起事件混淆嫁接**:「3 小時」屬 Axios;「上億下載 + 竊加密貨幣」屬 chalk/debug。

**chalk/debug(2025-09-08)— 「巨量下載 + crypto」主體**
- 維護者 Josh Junon(`qix`)收到偽冒 npm 的「2FA 重設」釣魚信(來自攻擊前 3 天註冊的 `npmjs.help`),即時被收走帳密 + TOTP。
- 18 個基礎套件(chalk/debug/ansi-styles…)合計**每週 ~26 億次下載**;payload 為純瀏覽器端 crypto drainer(在簽章前竄改錢包收款地址)。
- 時間窗(UTC):`13:16` 上架 → `~15:20` 示警 → 約 **2 小時**回退。
- **實際得手:極小**——鏈上追蹤實得約 **5 美分 ETH + ~$20 迷因幣**(報告標題〈Oops, No Victims: The Largest Supply Chain Attack Stole 5 Cents〉)。

**Axios(2026-03-31)— 「3 小時」出處**
- 維護者帳號被奪;歸因北韓 nexus(GTIG = UNC1069;微軟 = Sapphire Sleet)。
- 惡意版 axios 1.14.1 / 0.30.4 注入假依賴 `plain-crypto-js`,post-install 下載跨平台 RAT(WAVESHAPER.V2)——**非竊幣、是間諜 RAT**。
- 時間窗:`00:21` 發布 → `03:15` 移除,約 **3 小時**;惡意版本窗口內實際被拉取約 **60 萬次**;axios 主線 >1 億次/週。

**⚠️ 事實校正**:
1. 「上億/數十億下載」= **套件下載基數**,不是惡意版本被拉取次數(Axios 實際 ~60 萬次)。**曝險巨大 ≠ 實損巨大**。
2. 「3 小時」屬 Axios;「crypto drainer + 上億下載」屬 chalk/debug,不可混。
3. 惡意碼性質不同:chalk/debug 是**前端竊幣**;Axios 是**安裝期 RAT**。

---

## 2.3 GitHub 假倉庫木馬 — SEO/搜尋投毒(以 DeepSeek-TUI 假 fork 為例)

> 本案核心事實來自資安研究者 **探姬(@ProbiusOfficial,Hello-CTF 作者)本人公開的事故復盤**。原文出處:[X @ProbiusOfficial](https://x.com/ProbiusOfficial)(轉載討論見 [linux.do topic 2237885](https://linux.do/t/topic/2237885))。本節為摘要與技術整理,完整細節請見原作者一手復盤。

**概述**:研究者比賽前夕想試用爆紅終端 AI 工具,誤下載一個**惡意 fork**:約 **300+ star、上過 GitHub Trending、Bing 搜「DeepSeek-TUI」排第一**。原專案 `Hmbown/DeepSeek-TUI` 是安全的;惡意 fork 僅比原版大約 **2MB**,這 2MB 即一整套多階段 Rust 木馬。執行後其 X 帳號被盜。

**二次傳播(關鍵教訓)**:原惡意倉庫後被刪,但其本體**被多個知名專案收錄**(如一個 13k star 的倉庫包含它)、被 AI 推薦、部分 fork 保留帶毒 Release——即原倉庫消失仍持續擴散。

**帳號被盜時間線**:Day 0 下載執行;Day 1 Google 寄信提示「帳號信箱已被修改」未注意(X 有 24–48h 改信箱窗口期,錯過了);Day 2 帳號被強制下線;後續申訴找回。

**技術解剖(一手 IDA 分析)**:模組化多階段木馬家族,**至少 5 個同源 Rust 樣本**,共享 `memexec` 記憶體載入;具備註冊表 Run 鍵 / 計畫任務 `schtasks /ONLOGON /RL HIGHEST` / Winlogon Userinit / Startup .lnk 多重持久化、7 項反沙箱、RC4 解密(密鑰綁 PID)、無檔案記憶體執行;C2 走 Pastebin / Snippet.host raw。瀏覽器密碼/cookie 在此階段易被竊。

> **歸因註記**:技術細節為原作者一手分析;本案屬同期一波「假冒爆紅 AI 工具」GitHub 投毒潮,但不武斷歸入任何具名行動。

**攻擊手法本質**:惡意 repo 爬上搜尋/Trending 第一的手法——**刷 star/fork(機器人/Ghost 帳號)、頻繁無意義 commit 偽造「最近更新」、蹭熱門關鍵字 + 黑帽 SEO、付費刷星**。佐證規模:CMU/Socket「StarScout」研究估約 **600 萬疑似假 star**;Check Point「Stargazers Ghost Network」記錄 3,000+ Ghost 帳號的 Distribution-as-a-Service;Apiiro 2024-02 偵測 10 萬+ 惡意 repo。

**⚠️ 事實校正**:
- 「DeepSeek-TUI 是木馬」——錯;原專案安全,中毒的是**惡意 fork**。
- 「連大佬都中招 = 工具有問題」——因果倒置;中招源於**搜尋排名/star 被操控** + 在熱門期主動試用,非工具缺陷。
- 「star 數/Trending = 可信」——正是被利用的盲點(研究顯示 50 star 的 repo 已有約 15% 涉刷星)。

---

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

**Shai-Hulud(2025)— 自我複製蠕蟲**:惡意碼在 postinstall 竊憑證、把受害者私有 GitHub repo 改 public,若找到 npm 憑證則自動把蠕蟲注入該維護者套件並重發,**自我繁殖**。2.0 波及至少 **796 套件 / 1,092 版本**、25,000+ GitHub repo。**關鍵**:2.0 惡意版本**全帶有效 SLSA L3 provenance**——完整性防線全綠燈仍中毒(見[防禦現況](03_defense-landscape.md))。
