# 検証ランブック: 初回表示 → 再スキャン → 修正後再スキャン

このリポジトリのCI(`.github/workflows/sysdig-scan.yml`)を本番運用に載せる前に、
実際のSysdig Secureアカウント・実際のGitHub Code Scanning UIで一度は
手動確認しておくべき項目をまとめる。`tests/test_validate_sarif.py`は
`validate_sarif.py`自身のロジックの正しさしか保証しないため、GitHub側の
実際のアラート挙動(継続性・重要度表示・suppression)はここで確認する。

## 0. 前提条件チェックリスト(初回のみ)

- [ ] 対象リポジトリで **Code Scanning が利用可能** か確認する
      (Settings > Code security > Code scanning)。Private repoの場合は
      GitHub Advanced Securityが必要。
- [ ] 組織のポリシーでSARIFアップロード/Actionsの外部actionsの利用が
      禁止されていないか確認する(Organization Settings > Actions >
      General > Allow specified actions and reusable workflows)。
      `sysdiglabs/scan-action`と`github/codeql-action/upload-sarif`を
      許可リストに含める必要がある場合がある。
- [ ] GitHub Secretsに `SYSDIG_SECURE_TOKEN` を設定する。
      値をチャットやコミットに貼らないこと。
      ```
      gh secret set SYSDIG_SECURE_TOKEN --repo <owner>/<repo>
      ```
- [ ] 利用するSysdig Secureのリージョンに応じて repository variable
      `SYSDIG_SECURE_URL` を設定する(未設定時は`https://secure.sysdig.com`)。
      ```
      gh variable set SYSDIG_SECURE_URL --repo <owner>/<repo> --body "https://<region>.app.sysdig.com"
      ```
- [ ] ワークフローの`permissions`が`security-events: write`のみを
      最小付与していることを確認する(過剰な`write-all`等になっていないか)。

## 1. 初回スキャン: アラートの初期表示を確認する

1. `workflow_dispatch`でワークフローを実行する。
   ```
   gh workflow run sysdig-scan.yml --repo <owner>/<repo>
   ```
2. ジョブの`Sysdig CLI Scanner`ステップのログで、検出件数と重要度別の
   内訳を確認する。
3. GitHubの **Security > Code scanning alerts** タブを開き、以下を確認する。
   - 検出件数がスキャナーのログと一致するか(重複ruleIdによる見かけ上の
     マージ・欠落が起きていないか)。
   - 同じCVEが複数パッケージに存在する場合、**別々のアラートとして表示
     されているか**(1つに統合されてしまっていないか)。
   - 各アラートの重要度バッジが、Sysdig側のseverityと対応しているか
     (`rule.properties["security-severity"]`の値をSARIFファイルで
     直接確認し、GitHub UIの表示と突き合わせる)。
4. 各アラートを開き、"Rule"の説明が実際に対応するパッケージを正しく
   指しているか確認する(重複ruleIdバグが再発していると、無関係な
   パッケージが説明に出てくる - `sysdiglabs/scan-action#113`と同種の症状)。

## 2. 同じイメージを再スキャン: アラートの継続性を確認する

コードやDockerfileを変更せずに、同じワークフローを再実行する。

```
gh workflow run sysdig-scan.yml --repo <owner>/<repo>
```

確認ポイント:

- [ ] Code scanning alertsの件数が **増えていない**(同じ検出が新規
      アラートとして重複作成されていない)。
- [ ] 各アラートの "最新検出日時(Last detected)" だけが更新され、
      アラートID自体は変わっていない。
- [ ] 1回目に手動でdismiss/triageした場合、その状態が2回目の
      アップロード後も維持されている。

ここで件数が増えてしまう場合、`partialFingerprints`または`ruleId`が
実行ごとに変化していないか、SARIFファイルを直接diffして確認する
(`jq '.runs[0].results[].ruleId' sarif.json | sort`など)。

## 3. 修正後の再スキャン: 解消したアラートの扱いを確認する

`sample-app/Dockerfile`のベースイメージを、脆弱性が修正された(または
少ない)タグに変更し、再度ワークフローを実行する。

確認ポイント:

- [ ] 修正されたCVEに対応するアラートが **Closed(Fixed)** になるか。
- [ ] 修正されていないCVEのアラートは継続してOpenのままか
      (誤ってCloseされていないか)。
- [ ] `exclude-accepted: false`(デフォルト)のまま運用している場合、
      Sysdig Secure側でaccepted riskにした脆弱性がSARIFの
      `suppressions`としてどう表現されるか、再アップロード後もGitHub側で
      "Dismissed"状態が維持されるかを実データで確認する。
      `exclude-accepted: true`にすると該当項目がレポートから完全に
      消えるため、監査ログとしての追跡性は失われる。どちらの方針を
      取るかはこの実データ確認の結果で決める。

## 4. カテゴリ運用の確認

このリポジトリではVMスキャン結果に固定カテゴリ`sysdig-vm-sample-app`を
使っている(`.github/workflows/sysdig-scan.yml`の`SARIF_CATEGORY`)。
IaCスキャンなど別の分析を追加する場合は、必ず別のcategory値
(例: `sysdig-iac-sample-app`)を割り、以下を確認する。

- [ ] 複数categoryのSARIFをアップロードしても、Code scanning alerts上で
      互いのアラートが上書き・混同されないこと。
- [ ] 同じcategoryへの再アップロードは、そのcategoryの既存アラート
      セットを正しく更新する(新category作成時のみ、既存アラートが
      "stale"としてclose対象になる挙動を含む)。

## 5. 実施結果(2026-09-28, `Qfour/sysdig-cli-scanner-demo`, リージョンAU1)

このリポジトリ自体で1〜3を実際に実行して確認した結果を記録する。

**リージョン設定の罠**: `SYSDIG_SECURE_URL`未設定(デフォルト
`https://secure.sysdig.com`, US1)でトークンを投げたところ、
「Sysdig Secure Token is required」エラーではなく
`Unable to retrieve MainDB ... Exiting now`という一見無関係な
エラーで失敗した。原因はトークンのリージョン(AU1)とAPI URLの
不一致。AU1の正しいエンドポイントは`https://app.au1.sysdig.com`
(Website URLとAPI Endpointが同一ドメイン)。エラーメッセージから
リージョン不一致だと直接分かるわけではないので、`Unable to
retrieve MainDB`が出たら真っ先にリージョン設定を疑うこと。

**手順1(初回スキャン)**: 5件検出(critical×2, high×2)。
`stop-on-failed-policy-eval: true`によりPolicy Evaluation FAILEDで
ジョブは失敗扱いになったが、`Verify SARIF was actually generated`
と`validate_sarif.py`は正常終了し、SARIFは正しくアップロードされた
(「検出あり」と「SARIF未生成」の分離が実際に機能)。5件それぞれが
`<pkg名>-<version>-<path>`形式の別ruleIdを持ち、Code Scanning側でも
5件の別アラートとして表示され、`security-severity`起因の重要度
バッジも正しく出た。一方`validate_sarif.py`は実データに対しても
警告を出した: 5/5件で`partialFingerprints`が欠落、全件`level=note`固定
(いずれも設計時にコード上のIssueから予想していた既知の不具合と一致)。

**手順2(同一イメージ再スキャン)**: 5件のアラート番号・`created_at`が
変化せず、新規アラートは作られなかった。`partialFingerprints`が
欠落していても、GitHubの`ruleId`+location基準のフォールバック照合で
アラート継続性が保たれることを確認した。

**手順3(修正後の再スキャン、重要な注意点)**: `sample-app/Dockerfile`で
Flask 1.1.2→1.1.4、Jinja2 2.11.2→2.11.3にpipアップグレードして
再スキャンしたところ、Flask-1.1.2とJinja2-2.11.2のアラートは
`state: fixed`になった。しかし実際のCVE本文を確認すると、Flask
1.1.4もJinja2 2.11.3も**同じCVE(CVE-2023-30861等)をまだ含んでいた**
(真の修正版はFlask 2.2.5+ / Jinja2 3.1.x+で、Python 2.7を維持する
制約上そこまで上げられない)。つまり実際に起きたのは:

- ruleIdが`pkg名-version-path`でバージョンを含むため、バージョンを
  上げた時点で**旧バージョンのruleIdのアラートは機械的にfixedになる**
  (脆弱性が解消されたかどうかとは無関係)。
- 同じCVEが新バージョンのruleId(`Flask-1.1.4-...`,
  `Jinja2-2.11.3-...`)で**新規アラートとして再度オープンした**。
- setuptools(OS側dist-packagesと重複してpipでアンインストールできず
  未変更)とWerkzeug/click(py2対応の新版が存在せず未変更)のアラートは
  期待通りopenのまま維持された。

**教訓**: このアラート追跡モデルは「パッケージの正確なバージョン」を
単位にしている。運用時は「Fixedになった」ことだけを見て「CVEが
解消された」と判断してはいけない。fixedになったアラートの直後に
同じCVEが新しいruleIdで再オープンしていないか(=見た目の入れ替えに
すぎないか)を、diff対象の期間でCode scanning alertsを`state=all`で
確認するまでがワンセットである。
