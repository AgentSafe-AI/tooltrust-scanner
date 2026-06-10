# Plan: 給 IOC pipeline 加一層 MCP/AI 相關性過濾

> 給執行者(sonnet)。全程在新 branch + PR,**不碰 main、不自動 merge**。

---

## 0. 背景

新 pipeline(已上線)每天從 OSV per-ecosystem feed 撈 `MAL-` 確認惡意套件,彙整成 digest PR。實測兩天(PR #50/#51)撈到 28 個,其中**只有 2 個跟 ToolTrust 的 MCP 領域相關**(`openai-mcp`、`tiktoken-mcp`,已 promote 進 AS-008)。其餘 26 個是 crypto typosquat(`solana-core-4`、`web3-tools-9`、`bittensor-burn`…)、銀行 typosquat、垃圾測試名 —— 全是真惡意,但跟 MCP 使用者無關,而且 AS-004 掃描時即時查 OSV 本來就覆蓋。

結果:每天逼人看 9-19 個 PR,只為挑出 1-2 個相關的。要加一層相關性過濾,讓 pipeline 只收 MCP/AI 領域的惡意套件。

## 0.5 關鍵:這層過濾跟「被幹掉的關鍵字猜測」本質不同(務必讀懂)

上一版的禍根是 `hasStrongCompromiseSignal`:在**所有 CVE** 上用關鍵字猜「這是不是供應鏈攻擊」。失敗原因是攻擊「手法詞」(account takeover、malicious)跟一般漏洞描述詞重疊,無法分離。

這層過濾不一樣,兩個關鍵差異:

1. **基礎集合已經是「確認惡意」**(MAL- 記錄),不是在猜惡意。過濾只是在確定惡意的前提下,再篩「屬不屬於 MCP/AI 領域」。
2. **篩的是領域歸屬,不是攻擊類型**。領域關鍵字(`mcp`、`openai`、`anthropic`、`langchain`、`tiktoken`)是領域特定的專有名詞,不會出現在無關套件名裡。`solana-core-4` 不含任何 MCP/AI 詞,`openai-mcp` 含。這個區分是乾淨的。

但仍有風險:一個名字不含 AI 詞的 typosquat(如偽裝 `requests`)若被用在 MCP 依賴鏈裡,會被漏掉。**第一版接受這個漏失** —— 因為這類本來就靠 AS-004 即時查覆蓋,且寧可漏一點也不要又變 noise。未來可加 Tier 2 watch-list(見第 5 節),但不在本次範圍。

**持續把關機制**:跟上次一樣,用真實樣本建 negative/positive 測試表,讓「加關鍵字」這件事永遠有對抗性測試把關。

## 1. 設計

在 `scripts/ioc-candidates/fetch.go` 加一層 gate:MAL- 記錄必須同時「是惡意」且「MCP/AI 相關」才產生候選。

判斷依據:套件名(主)+ summary/details(輔)比對一組**高精確**的 MCP/AI 領域關鍵字。第一版寧窄勿寬 —— 只收幾乎只出現在 AI/MCP context 的詞,避免 `agent`/`prompt`/`vector` 這類可能誤命中一般套件的寬詞。

## 2. 實作步驟

### Step A — 新增相關性判斷

```go
// mcpRelevanceKeywords are high-precision domain markers for the MCP / LLM
// tooling ecosystem. Intentionally narrow: every entry should almost never
// appear in an unrelated package name. Broad words (agent, prompt, vector,
// embedding, rag) are deliberately excluded to avoid false matches — add them
// only with a negative-test case proving they don't over-match.
var mcpRelevanceKeywords = []string{
	"mcp",
	"model-context-protocol",
	"modelcontextprotocol",
	"openai",
	"anthropic",
	"claude",
	"langchain",
	"langgraph",
	"llamaindex",
	"llama-index",
	"tiktoken",
	"huggingface",
	"ollama",
	"llm",
}

// isMCPRelevant reports whether a confirmed-malicious record targets the
// MCP / LLM tooling ecosystem (ToolTrust's scope), as opposed to unrelated
// malware (crypto typosquats, etc.) that AS-004's live OSV lookup already
// covers. Matches on package name first, then summary/details text.
func isMCPRelevant(vuln osvVulnerability) bool {
	hay := strings.ToLower(strings.Join([]string{
		vuln.Summary,
		vuln.Details,
	}, " "))
	for _, aff := range vuln.Affected {
		hay += " " + strings.ToLower(aff.Package.Name)
	}
	for _, kw := range mcpRelevanceKeywords {
		if strings.Contains(hay, kw) {
			return true
		}
	}
	return false
}
```

> 注意 `llm` 是子字串會命中 `llmnr` 之類嗎?在套件名/AI 描述脈絡裡風險低,但若 negative 測試發現誤命中,改成更嚴格的邊界比對或移除 `llm`。讓測試決定。

### Step B — 在 buildCandidates 加 gate

現在的迴圈(`isMaliciousPackageRecord` 之後):

```go
if !looksLikeBlacklistCandidate(*vuln) {
	continue
}
severity := maliciousPackageSeverity(*vuln)
```

改成:

```go
if !looksLikeBlacklistCandidate(*vuln) {
	continue
}
if !isMCPRelevant(*vuln) {
	continue
}
severity := maliciousPackageSeverity(*vuln)
```

### Step C — 可觀測性(輕量)

讓 pipeline 報告過濾了多少,方便日後判斷關鍵字夠不夠。在 `fetchCandidatesWithClient` 或 `run` 統計「看過的 MAL- 總數 vs 通過相關性的數量」,寫進 stderr warning 或 stdout summary。例如:

```
Wrote 2 IOC blacklist candidate(s) to ... (3 MCP-relevant of 28 malicious records seen)
```

實作不必精確到完美,有個量級即可。若改動範圍太大就跳過,non-blocking。

### Step D — 測試(關鍵:對抗性樣本表)

`scripts/ioc-candidates/fetch_test.go` 新增:

```go
func TestIsMCPRelevant_PositiveAndNegative(t *testing.T) {
	relevant := []string{
		"openai-mcp", "tiktoken-mcp", "claude-desktop-helper",
		"langchain-community-tools", "ollama-python-client",
		"anthropic-sdk-fork", "llamaindex-readers",
	}
	for _, name := range relevant {
		v := osvVulnerability{
			ID:      "MAL-2026-0001",
			Summary: "Malicious code in " + name,
			Affected: []osvAffected{{Package: struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			}{Name: name, Ecosystem: "PyPI"}}},
		}
		if !isMCPRelevant(v) {
			t.Errorf("expected MCP-relevant: %q", name)
		}
	}

	// Real crypto/typosquat samples from PR #50/#51 — must NOT match.
	irrelevant := []string{
		"solana-core-4", "web3-tools-9", "bittensor-burn", "spl-token-py",
		"solana-web3-py", "@bancolonbia/menu-filter-widget-web",
		"rsquests", "nhmpy", "xfoobar", "odoo-addon-spp-base",
	}
	for _, name := range irrelevant {
		v := osvVulnerability{
			ID:      "MAL-2026-0002",
			Summary: "Malicious code in " + name,
			Affected: []osvAffected{{Package: struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			}{Name: name, Ecosystem: "PyPI"}}},
		}
		if isMCPRelevant(v) {
			t.Errorf("crypto/unrelated package should not match MCP filter: %q", name)
		}
	}
}
```

同時更新既有的 `TestBuildCandidates_EmitsMaliciousPackageRecord`:它的測試 vuln 是 `qr-code-styling-temp`(不含 MCP 詞),加了相關性 gate 後**不該再產生候選**。把它的測試套件名改成一個 MCP 相關的(例如 `openai-mcp`),或改測試斷言。擇一,讓測試反映新行為。檢查所有現有測試,凡是依賴「非 MCP 套件會被收」的都要更新。

### Step E — workflow 文字

`.github/workflows/ioc-candidates.yml` 的 PR 標題/body:強調這些是 **MCP/AI 相關**的確認惡意套件,review 重點是確認後 promote 進 AS-008。

### Step F — 文件

`docs/IOC_PIPELINE.md` / `docs/ioc-pipeline.md`:加一段說明相關性過濾 —— pipeline 只收 MCP/AI 領域的 MAL- 套件;無關的惡意套件(crypto typosquat 等)交給 AS-004 即時查 OSV 覆蓋,不進此 pipeline。

## 3. 驗證

```bash
go build ./... && go test ./scripts/ioc-candidates/... -v && go test ./...

# 真實 feed 煙霧測試:過濾前後對比
go run ./scripts/ioc-candidates -since 720h -ecosystems npm,PyPI -out /tmp/mcp-cand.json -existing pkg/analyzer/data/blacklist.json
jq 'length' /tmp/mcp-cand.json
jq -r '.[].value' /tmp/mcp-cand.json   # 應該全是 mcp/openai/anthropic/langchain... 相關,不該有 solana/web3/bittensor
```

煙霧測試的 candidates 必須**全部**看得出 MCP/AI 相關性;若出現任何 crypto typosquat,關鍵字 gate 有漏,回去調 + 補 negative 測試。lint 0 issues、`git diff --check` 乾淨。

## 4. Git 流程

```bash
git checkout main && git pull origin main
git checkout -b feat/ioc-mcp-relevance
# 實作 + 驗證
git add -A && git commit && git push -u origin feat/ioc-mcp-relevance
gh pr create --repo AgentSafe-AI/tooltrust-scanner --title "..." --body "..."
```

Commit 訊息開頭:`feat: filter IOC candidates to MCP/AI-relevant malicious packages`,body 說明動機(28→2 的訊號收斂)、跟舊關鍵字猜測的本質區別、煙霧測試結果。結尾加 `Co-Authored-By: Claude Sonnet 4.6 (1M context) <noreply@anthropic.com>`。

**停在開 PR,不 merge。** 回報:PR 連結、煙霧測試過濾前(關掉 gate)vs 後的數量、go test 結果、任何 negative 測試逼你調整關鍵字的地方。

## 5. 完成判準

- [ ] `isMCPRelevant` + 高精確關鍵字清單
- [ ] buildCandidates 加相關性 gate
- [ ] 對抗性測試表(真實 crypto 樣本 negative + MCP 樣本 positive)全綠
- [ ] 既有測試更新(凡依賴「非 MCP 也收」的)
- [ ] workflow / 文件更新
- [ ] 煙霧測試:輸出全是 MCP/AI 相關,0 crypto typosquat
- [ ] go test ./... 綠、lint 0 issues
- [ ] PR 開好、未 merge、已回報

## 未來增強(不在本次範圍,別做)

- Tier 2 watch-list:無關的 MAL- 不丟棄而是記進 append-only log,供日後查詢。本次先丟棄(AS-004 已覆蓋)。
- 依賴鏈感知:偵測名字不含 AI 詞、但被 MCP 套件依賴的惡意套件。
