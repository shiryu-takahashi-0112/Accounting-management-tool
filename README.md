# 会計管理ツール

事業ごとのPL計画（実績連携）・販管費管理・CF管理・税額予測・複数年比較に対応した会計管理Webアプリです。
Cloudflare Workers + D1 上で動作し、メールアドレス/パスワードによるアカウント作成に対応しています。「メンバー管理」タブから招待リンクを発行すると、他のアカウントを同じワークスペース（事業データ）に招待して共同で管理できます。

## 構成

```
accounting-tool/
├── public/
│   └── index.html      # フロントエンド（単一HTMLファイル。ログイン/認証・PL/CF/販管費UIなど全て含む）
└── worker/
    ├── src/index.js     # バックエンドAPI（Cloudflare Workers）
    ├── schema.sql        # D1データベーススキーマ
    ├── wrangler.toml     # Workers設定（D1バインディング・静的アセット配信設定）
    └── package.json
```

- フロントエンドはWorkersの `[assets]` 機能で静的配信されます（`/api/` 以外の全リクエストは `public/index.html` にフォールバック）。
- バックエンドはメール/パスワード認証（PBKDF2-SHA256, 100,000回イテレーション）、セッショントークン方式（30日間有効）です。
- データは「ワークスペース」単位で管理されます（`workspaces` / `workspace_members` テーブル）。会員登録すると自動で自分専用のワークスペースが作られ、`businesses` / `accounts` / `entries` / `settings` はすべて `workspace_id` でスコープされます。「メンバー管理」タブから発行した招待リンク（`invites` テーブル、7日間有効・1回限り）を使うと、他のアカウントが同じワークスペースに参加し、事業データを共同編集できます。

## ローカル開発

```bash
cd worker
npm install
npm run db:apply-local   # ローカルD1にスキーマを適用（初回のみ）
npm run dev               # http://localhost:8787 で起動
```

## 本番デプロイ

デプロイ手順は [DEPLOY.md](./DEPLOY.md) を参照してください。
