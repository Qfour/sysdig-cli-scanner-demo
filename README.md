# sysdig-cli-scanner-demo

Sysdig CLI Scannerでコンテナイメージをスキャンし、SARIF形式でGitHub Code
Scanningに結果を届けるCIのリファレンス実装。「アップロードできること」
より「同じ検出を次回も同じアラートとして追跡できること」を優先して設計している。

## 構成

```
sample-app/Dockerfile          既知CVEを含む公式ダミー脆弱アプリ(sysdiglabs/dummy-vuln-app)
.github/workflows/
  sysdig-scan.yml              build → scan → SARIF検証 → upload-sarif → 差分レポート
  test-validator.yml           validate_sarif.py/scan_report.pyのユニットテスト(secrets不要、PRでも実行可)
scripts/
  validate_sarif.py            アップロード前のハードゲート(スキーマ/重複ruleId/URI/severity/fingerprint)
  scan_report.py                scanReport(JSON)からCVE単位の差分(New/Fixed)を計算しSummary/artifactに出力
  schemas/sarif-2.1.0-schema.json  ベンダリングしたSARIF 2.1.0スキーマ
tests/
  fixtures/                    group-by-package出力/scanReportを模したフィクスチャ
  test_validate_sarif.py       アラート同一性(同一CVE×複数パッケージ/再スキャン継続性)のテスト
  test_scan_report.py          New/Fixedの差分計算ロジックのテスト
docs/runbook.md                初回表示→再スキャン→修正後再スキャンの実データ確認手順
```

## セットアップ

1. Code Scanningが有効か、Organization Actionsポリシーが
   `sysdiglabs/scan-action`と`github/codeql-action/upload-sarif`を許可しているかを
   先に確認する(`docs/runbook.md`の0節)。
2. GitHub Secretsに`SYSDIG_SECURE_TOKEN`を設定する。
3. 必要であればrepository variableの`SYSDIG_SECURE_URL`を利用リージョンに
   合わせて設定する(未設定時は`https://secure.sysdig.com`)。
4. `.github/workflows/sysdig-scan.yml`を`workflow_dispatch`で実行する。

## 設計判断とその根拠

### スキャン単位とcategoryを固定する

`SARIF_CATEGORY: sysdig-vm-sample-app`を実行ごとに変わらない値として
ワークフロー内に固定している。VM/IaCなど分析種別を増やす場合は
category自体を分けることを`docs/runbook.md`の4節に明記した。

### group-by-package: true を明示指定する(重要な訂正)

当初の想定では「`group-by-package: true`利用時に重複ruleでアップロードが
拒否された」という前提だったが、`sysdiglabs/scan-action`の実際のIssue
([#113](https://github.com/sysdiglabs/scan-action/issues/113))を確認した
結果、事実は逆だった。

- 重複ruleIdの**未修正の**既知バグがあるのはデフォルト(`false`, per-vulnerability
  モード)側。`ruleIds`という配列に対して`in`演算子を使ってしまっており、
  dedupeガードが常に素通りする。実測で195ルール中63個が重複。
- `group-by-package: true`側にも過去に別の重複バグ(#95: ruleIdが
  `pkg.name`だけでバージョン/パスを含まず衝突)があったが、これは
  `${pkg.name}-${pkg.version}-${pkg.path}`をIDに使う形で**修正済み**。
- さらに設計上も、per-vulnerabilityモードのruleIdはCVE単体であり、
  そもそも同じCVEが複数パッケージにあるケースを区別する作りになっていない。
  group-by-packageモードはパッケージ単位でruleIdが分かれるため、
  「同じCVEが複数パッケージにある場合に検出が一つにまとまる」問題への
  直接的な対策になる。
- また、GitHub側の実際の挙動は「アップロード拒否」ではなく「寛容な
  デデュプリケーション」で、rules配列が縮退し、アラートの説明文が
  任意の1パッケージを指す不整合が起きる(サイレントに紛らわしくなる方が
  ハードエラーより厄介)。

この経緯から、ワークフローでは`group-by-package: true`を明示指定し、
かつ`validate_sarif.py`で重複ruleIdをハードゲートとして重ねて検証する
(将来デフォルト挙動が変わった場合や、フィルタ設定を変えた場合の
リグレッションを検出するため)。

### アップロード前の妥当性確認(`scripts/validate_sarif.py`)

- SARIF 2.1.0スキーマ検証(ベンダリングした公式スキーマに対して`jsonschema`で検証)。
- `tool.driver.rules[].id`の重複検出(見つかった場合は例外的にexit 2、
  アップロードステップに進めない)。
- 各resultの`artifactLocation.uri`が空・絶対パスでないことを検証する。
- `rule.properties["security-severity"]`の欠落を警告する
  (GitHubの重要度バッジはこのプロパティを見ており、`result.level`は
  見ていない。Sysdig側には`result.level`が重要度と無関係に`note`固定に
  なるバグがあるため、この点を明示している)。
- `partialFingerprints`の欠落を警告する(再スキャン時の同一性追跡が
  GitHub側の推測フィンガープリントに委ねられるため、要注意サインとして扱う)。
- **SARIFファイルが存在しない・壊れている場合はexit 2**、
  **`results: []`(検出0件)は正常なexit 0**として明確に区別する。

### 「検出あり」と「スキャン失敗」の分離

`sysdig-scan.yml`では、ポリシー違反時に`stop-on-failed-policy-eval: true`で
ジョブを失敗扱いにしつつ、後続の検証/アップロードステップには
`if: success() || failure()`を付与している。一方、SARIF未生成・破損は
`Verify SARIF was actually generated`ステップと`validate_sarif.py`自身が
独立してexit 1/2で検出し、「検出0件」に読み替えられないようにしている。

### 権限

`security-events: write`に加え、private repoでの`upload-sarif`実行に
`actions: read`が必要という点をGitHub公式Issue
([codeql-action#2117](https://github.com/github/codeql-action/issues/2117))で確認し、
最小権限セットとして`contents: read` / `security-events: write` / `actions: read`
の3つのみを付与している。

### Security Reporting(scan summary + 差分管理)

GitHub Actionsの実行画面には2種類のレポートが出る。

1. **`sysdiglabs/scan-action`自身のネイティブSummary**
   (`skip-summary`は未指定=既定`false`なので有効)。severity別の
   Vulnerabilities summaryテーブルと、Dockerfileレイヤー単位の
   パッケージ別脆弱性テーブルがActionsの「Summary」タブに出る。
2. **`scripts/scan_report.py`が追記する差分セクション**
   (`## Vulnerability diff since previous scan`)。scanReport
   (JSON, `steps.scan.outputs.scanReport`)をCVE単位でパースし、
   前回実行時の検出内容(baseline)と比較して🆕New/✅Fixedを表示する。
   baselineは`actions/cache`でジョブ間に持ち越す
   (key: `sysdig-baseline-${SARIF_CATEGORY}-${run_id}`、
   restore-keysで直前のrunのキャッシュを前方一致で復元する
   ローリングキャッシュ方式)。

差分の識別キーはSARIFのruleIdスキームと同じ
`(package名, version, path, CVE)`。理由は上と同じで、同じCVEが
別バージョン/別パスに現れた場合を "変化なし" と誤認しないため。

**Fixed = CVE解消ではないことに注意**(`docs/runbook.md`5節で実証済み):
パッケージのバージョンが変わるとruleId/識別キーも変わるため、
CVEが実際には残っていてもFixed扱いになり、同じCVEが新バージョンの
findingとして再度Newに出ることがある。`vulnerability-report.md`にも
この注記を出力している。

**発行される成果物**: `sysdig-scan-reports-<run_id>`という名前で
以下をartifactとしてアップロードする(既定90日保持)。

- SARIF (`sarifReport`)
- 生のscanReport JSON(`scanReport`、フィルタ前の全脆弱性を含む)
- `vulnerability-report.md` / `.json`(CVE単位のNew/Fixed差分+
  全件テーブル)

## 未確認・実データ確認が必要な項目

以下はコード上のロジックでは保証できず、実際のSysdig Secure
アカウント・実際のリポジトリで確認する必要がある。`docs/runbook.md`に
手順を用意した。

- 同一イメージの再スキャンでアラートが本当に同一IDとして継続するか。
- accepted riskのSARIF suppressionがGitHub上で"Dismissed"として
  正しく維持されるか、再アップロード後も崩れないか。
- 組織のActionsポリシーがSARIFアップロードを妨げていないか。
