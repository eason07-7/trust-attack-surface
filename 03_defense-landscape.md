# 3. 防禦現況與開放問題

> 沿「安裝前 / 安裝時 / 安裝後」盤點防禦,標成熟度 `[已實作-產品]` / `[研究中-學術]` / `[概念討論]`,並以客觀立場列出**領域開放問題**。

---

## 3.0 一個決定性事實:完整性 ≠ 安全

2025 年的 **Shai-Hulud** npm 蠕蟲,惡意版本**全帶有效的 SLSA Build Level 3 provenance 簽章**。據報導(Mend 追蹤,VentureBeat):*"Every malicious version carried a valid SLSA Build Level 3 provenance attestation. The provenance was real."* 一個受害專案「紙面上設定全對:OIDC trusted publishing、簽章 provenance、每個維護者帳號都開 2FA」,照樣淪陷;攻擊用「孤兒 commit(無父歷史)」技術——真正的控制點是 **OIDC scope**,而非 provenance/2FA。

> **結論**:完整性防線(簽章 / SBOM / provenance / 2FA)可以**全數通過,套件仍然是毒的**。現有防禦多在防「**完整性**(東西沒被竄改)」,但攻擊攻的是「**真實性**(合法主體本身就是惡意)」——這是結構性盲區。

**防治規律**:成本與可靠性沿安裝生命週期單調惡化。

| 生命週期段 | 防治目標 | 可靠性 | 成本 |
|---|---|---|---|
| 安裝前 | 別讓它進來/別執行 | 高(可阻斷) | 低 |
| 安裝時/執行時 | 進來了也限制它 | 中(可規避) | 中 |
| 安裝後(已淪陷) | 清除扎根生態 | 低(打地鼠,無除淨保證) | 高(常需重灌) |

---

## 3.1 安裝前(Pre-execution)

**選擇/搜尋時**:
| 方法 | 成熟度 | 說明 |
|---|---|---|
| OpenSSF Scorecard / deps.dev | 已實作-產品 | 安全實踐健康度評分;衡量「實踐」非「即時意圖」(高分專案也可能惡意) |
| StarScout(CMU/NCSU/Socket) | 研究中-學術(開源) | 用 low-activity + lockstep 啟發式偵測假 star;離線批次、精緻養號可規避 |
| realstars / StarGuard | 研究中→早期原型 | 在 repo 頁顯示信任分;僅作用在 repo 頁、非搜尋結果頁 |
| typosquat 偵測(typomania/typogard/SpellBound) | 已實作+研究 | FP 與覆蓋取捨 |

**取得後、執行前(verify)**:
| 方法 | 成熟度 | 說明 |
|---|---|---|
| OSS Rebuild(Google,2025-07) | 已實作-產品 | 重建熱門套件並比對「發布物有無 source 沒有的碼」;不涵蓋任意 GitHub fork |
| Reproducible Builds + diffoscope | 已實作-產品 | source↔binary 人類可讀 diff;npm/PyPI 可重現性遠低於 Debian,比對多為手動 |
| npm provenance / SLSA + slsa-verifier | 已實作-產品 | 不證明 source 本身乾淨;採用率低 |
| 沙箱「引爆」(OpenSSF Package Analysis) | 已實作-開源 | gVisor 沙箱跑套件抓惡意行為;偵測導向、可反沙箱 |

**安裝行為攔截(install-time gating)**:
| 方法 | 成熟度 | 說明 |
|---|---|---|
| npm `--ignore-scripts` / `@lavamoat/allow-scripts` | 已實作-產品 | 預設停用 lifecycle script + allowlist——最實用的 postinstall 防治 |
| cooldown / `min-release-age`(npm 11.10+、Renovate) | 已實作-產品 | **僅延遲 24h 就能擋掉多數事件**(惡意版多在數小時內被下架) |
| Socket Firewall / Aikido Safe Chain | 已實作-產品(免費) | ephemeral proxy 攔 registry、裝前查情資;限制:本地 cache 命中失效、已知繞過 |
| Endor / Sonatype Repository Firewall | 已實作-產品(商用) | 坐在私有 registry 與公開 registry 間,惡意回 403 |

**管理面 / 政策**:私有 registry + allowlist、版本鎖定(lockfile / `npm ci` / pinning)、對「熱門新工具」審查 SOP、預編譯 release 不直接信任。

---

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

---

## 3.3 安裝後 / 已淪陷(Post-compromise)

一旦多階段木馬執行,對手是**一整套互為備份、扎根系統各角落的惡意生態**:清了註冊表 Run 還有計畫任務、刪了計畫任務 Winlogon 被改、修了還有 Startup .lnk、刪了落地檔記憶體 memexec 還在跑、重啟又被 `schtasks /ONLOGON` 重建。

**持久化 → MITRE ATT&CK**:Run 鍵/Startup(T1547.001)、計畫任務(T1053.005)、Winlogon(T1547.004)、WMI 事件(T1546.003)、記憶體注入/反射載入(T1055 / T1620)。

**偵測工具與邊界**:
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

---

## 3.4 防禦缺口與領域開放問題(客觀觀察)

綜合三段防禦,以下問題目前**沒有成熟、可規模化的解法**,屬本領域公認的開放問題:

1. **「合法主體 × 惡意意圖」本身**:完整性 / 簽章 / provenance 體系**結構上無法處理**(Shai-Hulud 帶有效 SLSA L3 是鐵證)。
2. **維護者長線社工接班(XZ 模式)**:學界(如 *Beneath the Mask*, arXiv:2508.13453)明文指出「**目前不存在監控與識別跨專案異常貢獻者行為的工具**」;接班治理仍停在討論層。
3. **帳號劫持後的合法發布**:staged publishing + 2FA 只抬門檻,釣 MFA 可繞、OIDC scope 設錯仍被攻破。
4. **SEO / 搜尋投毒 + 假 repo + 認知信任層**:**最嚴重的真空**。不經受信任套件管道 → SBOM/掃描/provenance/firewall 全部無關;現有「防禦」幾乎只剩事後端點偵測(EDR)。**「開發者搜尋→點第一名→下載執行」這個認知環節幾乎零保護**。
5. **0-day 惡意套件**:known-CVE 掃描層(OSV/Dependabot/Snyk 核心)對「無 CVE 的新惡意」全 miss;行為層是唯一補位但可規避。
6. **LLM 語意審計尚不可靠**:幻覺、多階段狀態維持失敗、依賴 source repo 完整性(社工攻陷即失效)、需人類覆核——尚不能當自動化信任閘。

**一個反直覺的研究發現**:Shen, Sood & Weitzel《Social Proof is in the Pudding》(Journal of Online Trust and Safety, 2026,同儕審查)以真實田野實驗「買 star」,**找不到對下載的可辨識因果影響**。意涵:「反刷星」的主要價值在**抓惡意/詐欺信號**(惡意者仍在刷),而真正驅動「點第一名→下載」的更可能是**搜尋排名/SEO 與文件可信度**,而非 star 數本身。(單一研究、樣本為新建套件,外推須謹慎。)
