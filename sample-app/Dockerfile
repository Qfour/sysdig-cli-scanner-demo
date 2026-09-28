# Sysdig公式のダミー脆弱アプリをそのまま利用する。
# 既知CVEを安定して含むことがSysdig自身のscan-action README例でも保証されており、
# EOLディストリを自前で選ぶより再現性が高い。
FROM sysdiglabs/dummy-vuln-app:latest

# 検証ランブック(docs/runbook.md)手順3「修正後の再スキャン」用の修正。
# ベースはPython 2.7(EOL)のため、click/Werkzeugはこれ以上新しいpy2対応版が
# 存在せず、setuptoolsはOS側(dpkg)のdist-packagesと重複していてpipでは
# 安全にアンインストールできない。Flask/Jinja2だけがpy2のまま安全にCVE修正
# 済みバージョンへ更新できる、という制約込みで「一部のアラートは修正され、
# 一部は修正されないまま残る」という実運用に近い状態を作る。
RUN pip install --no-cache-dir Flask==1.1.4 Jinja2==2.11.3
