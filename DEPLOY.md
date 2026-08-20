# デプロイ手順（Cloudflare Workers + D1）

このツールはCloudflareアカウントへのデプロイ権限がこの環境からは操作できないため、以下の手順をご自身のPC、またはCloudflareダッシュボードから実行してください。

## 前提

- Cloudflareアカウント（無料プランで可）
- Node.js 18以上
- `npm install -g wrangler` または `npx wrangler` が使えること

## 手順

### 1. リポジトリを取得

```bash
git clone <このリポジトリのURL>
cd accounting-tool/worker
npm install
```

### 2. Cloudflareにログイン

```bash
npx wrangler login
```

ブラウザが開くのでCloudflareアカウントでログイン・認可してください。

### 3. 本番用D1データベースを作成

```bash
npx wrangler d1 create accounting_tool
```

実行すると以下のような出力が得られます。

```
[[d1_databases]]
binding = "DB"
database_name = "accounting_tool"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

この `database_id` の値をコピーし、`worker/wrangler.toml` 内の `database_id = "00000000-0000-0000-0000-000000000000"` を実際の値に書き換えてください。

### 4. スキーマを本番D1に適用

```bash
npm run db:apply-remote
```

### 5. デプロイ

```bash
npm run deploy
```

成功すると `https://accounting-tool.<あなたのサブドメイン>.workers.dev` のようなURLが発行され、そこからツールにアクセスできるようになります。

### 6. （任意）カスタムドメインの設定

Cloudflareダッシュボード → Workers & Pages → 該当Worker → Settings → Domains & Routes から独自ドメインを割り当てられます。

### 7. （任意）GitHub連携による自動デプロイ

GitHubリポジトリと連携すると、`main` ブランチへのpushで自動デプロイされるようになります。

1. Cloudflareダッシュボード → Workers & Pages → Create → Workers → "Import a repository" を選択
2. このリポジトリを選択し、ルートディレクトリを `worker` に設定
3. ビルドコマンドは不要（静的アセットは `public/` からそのまま配信されます）
4. D1データベースのバインディング（`DB` → `accounting_tool`）をダッシュボード上で設定

以降はpushするだけで自動的に本番反映されます。

## 注意事項

- 初回デプロイ後、ユーザー登録（新規会員登録）はツールの画面から誰でも行えます。社内利用など、登録者を制限したい場合は将来的に招待制やドメイン制限の追加実装を検討してください。
- `wrangler.toml` の `database_id` は本番用に書き換えた後、コミットして構いません（機密情報ではありません）。
