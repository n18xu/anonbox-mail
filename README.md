# AnonBox Mail

エンドツーエンド暗号化の使い捨てメールサービス。<https://anonbox.email> で稼働しています。

受信したメールは **サーバーに保存される前に暗号化** され、復号鍵はあなたのブラウザから出ません。
運営者を含め、サーバー側の誰も本文・件名・差出人を読むことはできません。

---

## 仕組み

```
差出人 ──▶ Cloudflare Email Routing ──▶ Worker ──▶ D1 (暗号文のみ)
                                          │
                                     公開鍵で暗号化
                                          │
ブラウザ ◀── 暗号文を取得 ──────────────────┘
   └─ パスワードから鍵を導出 → 秘密鍵を復号 → メールを復号
```

1. **アカウント作成時**、ブラウザで RSA-OAEP 2048bit の鍵ペアを生成します。
2. パスワードから PBKDF2-SHA256（600,000 回、アドレス由来のソルト）でマスター鍵を作り、HKDF で
   「秘密鍵をラップする鍵」と「サーバーに提示する検証値」に分けます。**パスワードそのものは端末から出ません。**
   秘密鍵はラップ鍵で AES-GCM 暗号化してから送るので、サーバーが受け取るのは暗号化済みの秘密鍵と検証値だけです。
   サーバーは検証値をさらに PBKDF2 でハッシュ化して保存します（DB が漏れてもログインには使えません）。
3. メールが届くと Worker が AES-256-GCM の使い捨て鍵で本文とメタ情報を暗号化し、その鍵をアカウントの**公開鍵**で暗号化して保存します。
4. 閲覧時はブラウザ内で、パスワード → 秘密鍵 → AES 鍵 → 本文、の順に復号します。

### サーバー側が保持しないもの

| | 保存内容 |
|---|---|
| メール本文・件名・差出人 | AES-256-GCM の暗号文のみ |
| 秘密鍵 | パスワード由来の鍵で暗号化された状態のみ |
| パスワード | 送信されない。端末で導出した検証値の PBKDF2 ハッシュのみ |

既存アカウント（auth v1）は、次回ログイン時に自動で v2 へ移行されます（`schema_migrate_authv2.sql`）。
ログイン試行にはレート制限があります（15分あたり8回失敗で一時ブロック）。

そのため **パスワードを忘れると復旧できません**。運営者によるパスワードリセットも（技術的に）不可能です。ハッシュだけ差し替えてもログインした先で秘密鍵が復号できず、過去のメールは読めなくなります。

---

## 機能

- 使い捨てメールアドレスの作成（ログイン制）
- **匿名エイリアス**：15桁の数字アドレスをいくつでも発行でき、同じ受信箱に届きます
- 受信一覧の**検索・未読フィルタ**（復号済みメタ情報に対してブラウザ内で実行、サーバーへは問い合わせません）
- **複数選択して一括削除**
- HTML メール表示（DOMPurify でサニタイズ後、スクリプト無効の iframe 内で描画）
- 認証コードの自動抽出とワンタップコピー
- Web Push 通知（VAPID）
- PWA（ホーム画面に追加可能）
- パスワード変更（秘密鍵を新パスワードで再暗号化するため、過去のメールはそのまま読めます）

---

## 構成

| | |
|---|---|
| `src/worker.js` | Cloudflare Worker。REST API・受信メールの暗号化保存・Web Push 送信・保持期間切れの削除 |
| `public/index.html` | フロントエンド（単一ファイル。ビルド不要） |
| `public/sw.js` | Service Worker（Push 通知の受信） |
| `schema.sql` | D1 のスキーマ |
| `scripts/gen-vapid.mjs` | VAPID 鍵ペアの生成 |

依存: [postal-mime](https://github.com/postalsys/postal-mime)（メール解析）、[DOMPurify](https://github.com/cure53/DOMPurify)（HTML サニタイズ）。

---

## 自分で動かす

```bash
npm install

# D1 を作成し、schema.sql を流し込む
npx wrangler d1 create <db-name>
npx wrangler d1 execute <db-name> --remote --file=schema.sql

# VAPID 鍵を生成（公開鍵は wrangler.toml、秘密鍵はシークレットへ）
node scripts/gen-vapid.mjs
npx wrangler secret put VAPID_PRIVATE_KEY

npx wrangler deploy
npx wrangler pages deploy public --project-name=<pages-project>
```

`wrangler.toml` の `DOMAIN`（`src/worker.js`）と `API_HOST`（`public/index.html`）を自分のドメインに合わせてください。
メールを受け取るには、Cloudflare の **Email Routing** を有効にし、catch-all の宛先をこの Worker に設定します。

### ローカル開発

```bash
npx wrangler dev --local --port 8787
python -m http.server 8099 --directory public
```

`localhost` で開いた場合、フロントエンドは自動的に `http://localhost:8787/api` を参照します。

---

## セキュリティ上の注意

- **パスワードはこの端末の IndexedDB に平文で保存されます**（設定画面で表示・コピーできるようにするため）。共用端末での利用は避けてください。ログアウトで消去されます。
- HTML メールの画像は既定で読み込みます。開封トラッキングが気になる場合は、本文表示時の「画像を隠す」で無効化できます。
- 受信したメールは既定で **30日後に自動削除** されます（`RETENTION_HOURS`）。
- この実装は E2EE ですが、サーバー側のコードが改変されれば配信されるフロントエンドも変えられます。**このリポジトリは、稼働中のコードを検証できるようにするために公開しています。**

---

## ライセンス

MIT
