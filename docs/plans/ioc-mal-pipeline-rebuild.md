# Plan: 重建 IOC pipeline — 從「猜 CVE 描述」改成「讀 OSV 確認的惡意套件 (MAL-)」

> 給執行者(sonnet)的藍圖。照步驟做,每步附驗證。全程在新 branch + PR,**不碰 main、不自動 merge**。

---

## 0. 背景與根因(讀懂再動手)

**現在的 pipeline 為什麼全是 noise:**

`scripts/ioc-candidates/fetch.go` 每天從 OSV 抓 npm/PyPI/Go 的 `all.zip`,然後用兩道 gate 篩:

1. `classifySeverity` + HIGH severity gate
2. `hasStrongCompromiseSignal` — 一串靠直覺維護的關鍵字(`"account takeover"`、`"malicious dependency"` …)去**猜**漏洞描述文字像不像供應鏈攻擊。

兩個結構性錯誤:

- **瞄錯層**:它撈的是「OSV 裡的 HIGH CVE」,而那一層是 AS-004(掃描時即時查 OSV)已經 cover 的普通 CVE。關鍵字猜測無法把「攻擊手法詞」和「攻擊類型詞」分開,所以撈出來幾乎全是普通 CVE 誤報。
- **致命矛盾**:OSV 真正標注「確認的惡意套件」用的是 `MAL-` 前綴的記錄,而**這些記錄沒有 `severity` 欄位**。現在的 HIGH severity gate 會把所有真正的惡意套件**直接濾掉**。也就是說現在的 pipeline 結構上不可能抓到供應鏈攻擊。

**已驗證的事實(plan 的地基):**

- OSV 已彙整 OpenSSF malicious-packages + GitHub Advisory + npm + PyPI 的確認惡意套件。**只接 OSV 一個 source 就涵蓋全部。**
- `MAL-` 記錄就在現在 pipeline 已經抓的同一個 bucket / per-ecosystem 路徑裡。實測:
  - `https://osv-vulnerabilities.storage.googleapis.com/npm/MAL-2026-4655.json` → HTTP 200
  - 結構:`id="MAL-2026-4655"`、`affected[0].package.name="qr-code-styling-temp"`、`ecosystem="npm"`、`versions=["9.9.10","9.9.11"]`、**無 `severity`**、`database_specific.malicious-packages-origins[].source="amazon-inspector"`、`credits=["Amazon Inspector"]`
- 每日新增量:npm 4–89/天、PyPI 2–12/天、Go 0/天。量適中 → 維持「每日彙整成一個 digest PR」即可,不要每筆開一個 PR。

**定位(重要,別做歪):** 這個 pipeline 是**情報入口**,不是要把 21 萬個 OSV MAL- 全塞進離線 blacklist。它每天把新增的確認惡意套件整理成一個 review-only digest PR,人從中挑真正高價值的(像 LiteLLM/Trivy 等級)手動 promote 進 AS-008。大量自動偵測的短命 typosquat 靠 AS-004 即時查 OSV 覆蓋即可。

---

## 1. 設計原則

1. **讀標記,不猜文字**:候選資格 = OSV 記錄是 `MAL-` 惡意套件記錄。`hasStrongCompromiseSignal` 整串關鍵字退役。
2. **MAL- 沒 severity**:移除 severity gate(對 MAL- 豁免)。產出的 entry severity 一律標 `CRITICAL`(確認惡意套件本來就該 BLOCK)。
3. **高信心**:每筆 MAL- confidence = `high`、suggested_action = `block`。
4. **可追溯**:把 `malicious-packages-origins[].source` 與 `credits` 寫進 notes,讓 reviewer 一眼判斷來源可信度。
5. **review-only 不變**:pipeline 不改 `blacklist.json` / `npm_iocs.json`,只開 digest PR。promote 仍是人工跑 `tooltrust-ioc-promote`。

---

## 2. 逐步實作

### Step A — `scripts/ioc-candidates/fetch.go`:解析 MAL- 來源歸屬

把 `osvVulnerability` 的 `DatabaseSpecific` 擴充,讓它能讀 `malicious-packages-origins`:

```go
DatabaseSpecific struct {
	Severity                 string `json:"severity"`
	MaliciousPackagesOrigins []struct {
		Source     string   `json:"source"`
		Versions   []string `json:"versions"`
		ImportTime string   `json:"import_time"`
	} `json:"malicious-packages-origins"`
} `json:"database_specific"`
```

同時確認 `Credits` 有被解析(若 struct 沒有就加):

```go
Credits []struct {
	Name string `json:"name"`
} `json:"credits"`
```

### Step B — 候選資格:`MAL-` 取代關鍵字猜測

刪掉整個 `hasStrongCompromiseSignal` 函式與 `strongSignals` 清單。新增:

```go
// isMaliciousPackageRecord reports whether an OSV record is a confirmed
// malicious package (OpenSSF malicious-packages / OSV "MAL-" namespace),
// as opposed to an ordinary CVE. These records carry no CVSS severity.
func isMaliciousPackageRecord(vuln osvVulnerability) bool {
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(vuln.ID)), "MAL-") {
		return true
	}
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(alias)), "MAL-") {
			return true
		}
	}
	return false
}
```

`looksLikeBlacklistCandidate` 改成委派給它(或直接全檔替換呼叫點):

```go
func looksLikeBlacklistCandidate(vuln osvVulnerability) bool {
	return isMaliciousPackageRecord(vuln)
}
```

### Step C — `buildCandidates`:移除 severity gate,改標 CRITICAL

現在的迴圈(約 280–348 行)有這段:

```go
severity, ok := classifySeverity(*vuln)
if !ok || severityRank(severity) < severityRank(minSeverity) {
	continue
}
if !looksLikeBlacklistCandidate(*vuln) {
	continue
}
```

改成(MAL- 沒 severity,先過資格再給固定 severity):

```go
if !looksLikeBlacklistCandidate(*vuln) {
	continue
}
severity := maliciousPackageSeverity(*vuln) // 見 Step D
```

`minSeverity` 參數對 MAL- 不再 gate。保留 flag(向後相容/未來可能用),但不要用它擋掉 MAL-。

### Step D — confidence / action / notes / severity:反映「確認惡意」

```go
func maliciousPackageSeverity(vuln osvVulnerability) string {
	// MAL- records carry no CVSS. A confirmed malicious package is always block-worthy.
	return "CRITICAL"
}

func candidateConfidence(vuln osvVulnerability) string { return "high" }

func suggestedActionForCandidate(vuln osvVulnerability) string { return "block" }

func candidateNotes(vuln osvVulnerability) string {
	origins := maliciousOriginSources(vuln)
	if len(origins) > 0 {
		return fmt.Sprintf(
			"OSV-confirmed malicious package (%s). Reported by: %s. Review affected versions before promoting to AS-008.",
			vuln.ID, strings.Join(origins, ", "),
		)
	}
	return fmt.Sprintf(
		"OSV-confirmed malicious package (%s). Review affected versions before promoting to AS-008.",
		vuln.ID,
	)
}

// maliciousOriginSources collects distinct reporting sources for the record,
// e.g. "amazon-inspector", "ossf-package-analysis", plus named credits.
func maliciousOriginSources(vuln osvVulnerability) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[strings.ToLower(s)]; ok {
			return
		}
		seen[strings.ToLower(s)] = struct{}{}
		out = append(out, s)
	}
	for _, o := range vuln.DatabaseSpecific.MaliciousPackagesOrigins {
		add(o.Source)
	}
	for _, c := range vuln.Credits {
		add(c.Name)
	}
	return out
}
```

> 註:`classifySeverity` / `severityRank` / `parseSeverityScore` 若已無其他呼叫點可一併刪除;若 `parseFlags` 仍用 `severityRank` 驗證 `-min-severity`,保留 `severityRank`,只刪 `classifySeverity` 那條死路徑。執行時用 `grep` 確認再刪,別留 dead code 也別誤刪。

### Step E — 測試:刪掉關鍵字猜測的全部測試,改成 MAL- 行為測試

`scripts/ioc-candidates/fetch_test.go` 刪除這些(全是針對已退役的關鍵字猜測):

- `TestBuildCandidates_SkipsOrdinaryCVEsWithMaliciousUserWording`
- `TestHasStrongCompromiseSignal_MaliciousDependencyPhrase`
- `TestHasStrongCompromiseSignal_MaintainerAccountTakeover`
- `TestHasStrongCompromiseSignal_OrdinaryAccountTakeoverDoesNotFire`
- `TestHasStrongCompromiseSignal_KnownFalsePositivePatterns`
- `TestBuildCandidates_SkipsOrdinaryCVEsWithCompromiseAndPackageWording`

新增:

```go
func TestBuildCandidates_EmitsMaliciousPackageRecord(t *testing.T) {
	now := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	vulns := []osvVulnerability{
		{
			ID:        "MAL-2026-4655",
			Summary:   "Malicious code in qr-code-styling-temp (npm)",
			Published: "2026-06-06T18:00:00Z",
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "qr-code-styling-temp", Ecosystem: "npm"},
					Versions: []string{"9.9.10", "9.9.11"},
				},
			},
		},
	}
	got := buildCandidates(vulns, "npm", map[string]struct{}{}, now, 24*time.Hour, "HIGH")
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate from MAL- record, got %d", len(got))
	}
	if got[0].Confidence != "high" || got[0].Severity != "CRITICAL" {
		t.Fatalf("MAL- candidate should be high/CRITICAL, got %s/%s", got[0].Confidence, got[0].Severity)
	}
}

func TestBuildCandidates_SkipsOrdinaryCVEEvenHighSeverity(t *testing.T) {
	now := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC)
	vulns := []osvVulnerability{
		{
			ID:        "GHSA-generic-2026-0001",
			Summary:   "Critical SSRF with account takeover and malicious dependency wording.",
			Published: "2026-06-06T18:00:00Z",
			Severity:  []osvSeverity{{Type: "CVSS_V3", Score: "9.8"}},
			Affected: []osvAffected{
				{
					Package: struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					}{Name: "genericpkg", Ecosystem: "npm"},
					Versions: []string{"1.2.3"},
				},
			},
		},
	}
	got := buildCandidates(vulns, "npm", map[string]struct{}{}, now, 24*time.Hour, "HIGH")
	if len(got) != 0 {
		t.Fatalf("ordinary CVE (no MAL- id) must never be a candidate, got %#v", got)
	}
}

func TestIsMaliciousPackageRecord_AliasMatch(t *testing.T) {
	v := osvVulnerability{ID: "GHSA-xxxx", Aliases: []string{"MAL-2026-9999"}}
	if !isMaliciousPackageRecord(v) {
		t.Fatal("MAL- in aliases should qualify")
	}
}
```

### Step F — golden fixture 換成 MAL-

`scripts/ioc-candidates/testdata/osv-response.json` 與 `candidates-expected.json` 目前是猜測時代的 fixture。重做:

1. 把 `osv-response.json` 換成幾筆真實感的 MAL- 記錄(可參考實際結構,含 `database_specific.malicious-packages-origins`)+ 一筆普通 GHSA CVE(用來證明它不會被選中)。
2. 重新產生 `candidates-expected.json`:只含 MAL- 那幾筆,severity=CRITICAL、confidence=high、notes 含來源。
   - 做法:先把 Step A–D 改完,跑 `go run ./scripts/ioc-candidates -ecosystems npm -feed-base-url <本地或固定> ...` 不方便的話,直接在 `TestBuildCandidates_Golden` 用新 input 跑一次、把實際輸出當 expected(但要人眼確認合理)。

> 若重做 golden 太纏,可把 `TestBuildCandidates_Golden` 降級為「用 inline vulns 驗證數量與關鍵欄位」,刪掉檔案型 golden。以行為測試(Step E)為主。擇一,別兩邊都留半套。

### Step G — workflow:`/.github/workflows/ioc-candidates.yml`

改文字與語意,不改架構(已經是每日一個 digest PR):

- PR 標題:`"threat-intel: ${count} OSV-confirmed malicious package(s) for review"`
- PR body 重寫,反映新語意:
  - 這些是 **OSV `MAL-` 確認的惡意套件**(來自 OpenSSF malicious-packages / Amazon Inspector / GitHub 等),不是普通 CVE。
  - review 重點改成:確認受影響版本範圍、是否值得進 AS-008 離線 blacklist(高價值/知名套件),還是靠 AS-004 即時查即可。
- `workflow_dispatch` 的 `min_severity` input:移除(對 MAL- 無意義)。`since` / `ecosystems` 保留。
- 對應移除 fetch step 裡的 `-min-severity "$MIN_SEVERITY"`(或保留 flag 但不再從 input 傳)。二擇一,保持一致。

### Step H — `.github/scripts/threat-intel-check.py`:移除寫死 axios 的 placeholder

`build_candidate_template` 是寫死 `if "axios" in hints` 的 demo,除了 axios 永遠回傳空。**移除候選萃取邏輯**,讓 threat-intel 回歸單純職責:RSS 有新文章 → 開 issue 提醒人讀。

- 刪 `build_candidate_template` 與 `CANDIDATE_DIR` 的候選檔寫入(`candidate_path.write_text(...)`)。
- issue body 裡「Candidate IOC file」那行移除或改成「Read the post, then add confirmed malicious packages via the OSV MAL- digest PR or manual blacklist edit」。
- workflow `threat-intel.yml` 裡 commit `.github/ioc-candidates` 的步驟若只為了存 placeholder 候選,一併簡化(state json 仍要存)。確認不破壞 state branch 機制。

### Step I — 文件

- `docs/IOC_PIPELINE.md` 與 `docs/ioc-pipeline.md`:更新流程描述。
  - 移除「summary/details 讀起來像供應鏈就收」這類描述。
  - 改成:「每日從 OSV per-ecosystem feed 過濾 `MAL-` 確認惡意套件,彙整成 review-only digest PR;人工挑選後用 `tooltrust-ioc-promote` 進 AS-008」。
  - 點明分工:普通 CVE → AS-004 即時查 OSV;確認惡意套件 → 此 pipeline 蒐集 + 人工 promote → AS-008。

---

## 3. 驗證(每步做完都跑)

```bash
# 編譯 + 全測試
go build ./...
go test ./scripts/ioc-candidates/... -v
go test ./...

# 真實 feed 煙霧測試:確認只出 MAL-、且真的有抓到東西
go run ./scripts/ioc-candidates \
  -since 720h -ecosystems npm,PyPI -out /tmp/mal-candidates.json \
  -existing pkg/analyzer/data/blacklist.json
jq 'length' /tmp/mal-candidates.json
jq -r '.[].blacklist_id // .[].source' /tmp/mal-candidates.json | head   # 應全是 MAL- 相關
jq -r '.[] | "\(.confidence) \(.severity) \(.value)"' /tmp/mal-candidates.json | head

# 反向確認:普通 CVE 不會混進來(抽查幾筆 source,應全部指向 MAL- 記錄)
```

煙霧測試的 candidates 必須:全部 confidence=high、severity=CRITICAL、每筆對得上一個 `MAL-` 記錄。若混進非 MAL- 的普通 CVE,Step B 的資格判斷有 bug,回去修。

`git diff --check` 要乾淨。`golangci-lint`(pre-commit 會跑)要 0 issues — 特別注意刪函式後不要留 unused import / dead code。

---

## 4. Git 流程(不碰 main、不自動 merge)

```bash
git checkout main && git pull origin main
git checkout -b feat/ioc-mal-pipeline
# ... 實作 + 驗證 ...
git add -A
git commit   # 見下方訊息
git push -u origin feat/ioc-mal-pipeline
gh pr create --repo AgentSafe-AI/tooltrust-scanner --title "..." --body "..."
```

Commit 訊息:

```
feat: rebuild IOC pipeline to read OSV-confirmed malicious packages (MAL-)

Replace the keyword-guessing filter (hasStrongCompromiseSignal) with
OSV MAL- namespace detection. The old filter scored ordinary CVE
description text and, fatally, gated on HIGH severity — which MAL-
records do not carry, so it could never surface a real malicious
package. It produced near-100% noise by re-doing AS-004's job.

New behavior: each daily run collects OSV-confirmed malicious packages
(OpenSSF malicious-packages / Amazon Inspector / GitHub, all already in
the OSV per-ecosystem feed) into one review-only digest PR. Confirmed
malicious packages are high-confidence, block-worthy, and carry source
attribution for triage. Humans still promote into AS-008 manually.

Also retires the hardcoded-axios placeholder in threat-intel-check.py so
that workflow returns to its real job: RSS new-post alerts.

Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>
```

PR body 要點:根因(severity gate 與 MAL- 不相容、關鍵字猜測重做 AS-004)、新訊號源(OSV MAL-,單一 source 涵蓋 OSSF+GHSA+npm+PyPI)、驗證結果(煙霧測試數量與抽查)、定位(情報入口非全量 blacklist)。

**停在開 PR。不要 merge。** 開完 PR 回報:PR 連結、煙霧測試實際撈到幾筆 MAL-、go test 結果。

---

## 5. 完成判準

- [ ] `hasStrongCompromiseSignal` + `strongSignals` 完全移除,無 dead code / unused import
- [ ] 候選資格 = `isMaliciousPackageRecord`(MAL- 前綴,含 alias)
- [ ] severity gate 對 MAL- 不再適用;產出 severity=CRITICAL、confidence=high
- [ ] notes 帶 `malicious-packages-origins` 來源
- [ ] 關鍵字猜測的舊測試全刪,新增 MAL- 行為測試 + golden 重做(或降級)
- [ ] workflow 文字/語意更新,移除 min_severity input
- [ ] threat-intel 的 axios placeholder 移除,RSS 提醒保留
- [ ] 文件更新
- [ ] `go test ./...` 綠、煙霧測試只出 MAL-、lint 0 issues
- [ ] PR 開好、未 merge、已回報
```