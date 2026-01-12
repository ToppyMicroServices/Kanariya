
# Kanariya TODO (AI-assisted bootstrap)

目的：Cloudflare（DNS / Workers / KV / WAF）設定〜バックエンド実装〜テスト〜簡易UIまでを、可能な限り **API + スクリプト + CI** で自動化する。

## 自動化の前提と限界

- 自動化できる：Cloudflare API / Wrangler CLI を用いた **再現可能なプロビジョニング**、コード生成、テスト生成、CI実行。
- 人のサポートが必要（最低限）：
  - **Cloudflare API Tokenの発行**（初回のみ、権限付与は手動が安全）
  - **ドメイン/ゾーンの所有確認・課金/プラン**（環境依存）
  - **Secret値の確定と投入**（`IP_HMAC_KEY`, `ADMIN_KEY`, `WEBHOOK_URL` 等。漏えい防止のため手動または安全なSecret Manager経由推奨）
  - **最終レビュー**（誤設定でDoS/情報露出になるため、WAF/RateLimit/Accessは人が確認する）

---

## Phase 0: 仕様固定（MVPのゴール）

- [x] (AI) MVP spec v0.1 を README と整合（API/ログ/通知/保持/重複抑制）
- [x] (AI) デフォルト値を固定：
  - [x] イベント保持：30日（Public MVP）
  - [x] dedupe TTL：30分
  - [x] `/admin/*` は後段で Access 化（MVPは `ADMIN_KEY` で暫定）

---

## Phase 1: 認証・権限（Token作成・権限設計）

### 1-1. Cloudflare API Token設計（最小権限）

- [x] (AI) 必要権限のリスト化（zone / dns / workers / kv / rules）
- [x] (Human) Cloudflare Dashboardで API Token を発行（推奨：目的別に分割）
  - [ ] `CF_TOKEN_PROVISION`（プロビジョニング用：DNS/Workers/KV/Routes）
  - [ ] `CF_TOKEN_READONLY`（検証用：read-only）
- [x] (Human) Tokenを安全に保管（1Password/Keychain/Secret Manager）

### 1-2. 権限確認（API疎通）

- [x] (AI) `scripts/cf_check_access.{py|ts}` を作る（zone取得、権限不足を明示）
- [x] (Human) ローカルで `CF_API_TOKEN` を設定して実行
- [x] (AI) 失敗時のメッセージ（どの権限が不足か）を整える

---

## Phase 2: サーバ設定をAPI経由で構築（Cloudflare）

### 2-1. 設定スクリプト（idempotent）

方針：何度実行しても同じ最終状態になるようにする（冪等）。

- [x] (AI) `scripts/cf_bootstrap.{py|ts}` を作る（以下を順に実行）
  - [x] Zoneの特定（`toppymicros.com`）
  - [x] DNSレコード作成：`kanariya.toppymicros.com`（proxied=ON）
  - [x] Workers KV namespace 作成：`KANARI_KV`
  - [x] Worker ルート設定：
    - [x] `kanariya.toppymicros.com/canary/*`
    - [x] （任意）`kanariya.toppymicros.com/admin/*`
- [x] (推奨) WAF/Rate limit ルール（最初は緩く、後で調整）：
    - [x] `/canary/*` への過剰リクエスト制限（Worker側の簡易レート制限）
    - [x] `/admin/*` は challenge/block（ADMIN_KEYでブロック）
- [x] (AI) 実行結果を JSON で出力（作成/既存/変更の差分）
- [x] (Human) 初回は dry-run を見てレビュー

### 2-2. Wrangler連携（デプロイ）

- [x] (AI) `wrangler.toml` の雛形を用意（routes/kv binding）
- [x] (AI) `scripts/wrangler_deploy.sh` を作る
  - [x] `wrangler deploy`
  - [x] `wrangler kv namespace list` からID取得→toml反映（または手動で固定）
- [x] (Human) Secret投入（安全のため原則手動）
  - [x] `wrangler secret put IP_HMAC_KEY`
  - [x] `wrangler secret put ADMIN_KEY`
  - [x] `wrangler secret put WEBHOOK_URL`（任意）

> ここは「完全自動化」も可能だが、SecretをCIへ流す設計が必要で、最初は人手が安全。

---

## Phase 3: バックエンド実装（Workers）

- [x] (AI) `src/worker.js`（or TS）を実装
  - [x] `GET /canary/:token` でイベント保存 + 通知
  - [x] IPはHMAC化して保存（平文IPを残さない）
  - [x] dedupe key（`token+ipHash+uaHash`）で通知抑制
  - [x] 204応答
  - [x] （任意）`GET /admin/export`（ADMIN_KEYで保護）
- [x] (AI) 例外系：KV失敗時の挙動（落とす/無通知）を固定
- [x] (AI) ルール：保存しない項目（body/queryの最小化）をコメントに明記

---

## Phase 4: 実行（自動実行 / CI）

### 4-1. ローカル実行

- [x] (AI) `make dev`（wrangler dev）でローカル起動
- [x] (Human) ローカルで smoke（curl）確認

### 4-2. GitHub Actions

- [x] (AI) `.github/workflows/deploy.yml` を作る（手動実行 + main push）
- [x] (Human) Repo Secretsに投入：
  - [x] `CF_API_TOKEN`（最小権限）
  - [x] `IP_HMAC_KEY` / `ADMIN_KEY` / `WEBHOOK_URL`
- [x] (AI) CIで `wrangler deploy` まで自動化

---

## Phase 5: テスト作成（自動生成 + 実行）

### 5-1. Unit tests（ローカル）

- [x] (AI) `vitest` 等で Worker単体テスト
  - [x] `/canary` が 204 を返す
  - [x] KVにイベントが保存される
  - [x] dedupeが効く（2回目は通知しない）
  - [x] `ipHash` が生成される

### 5-2. Integration / Smoke（本番）

- [x] (AI) `scripts/smoke_test.sh` を作る
  - [x] `/canary/<token>?src=smoke` へGET
  - [x] `admin/export`（有効時）でイベントが取れる
- [x] (Human) 最初の一回はWebhook通知を目視確認

---

## Phase 6: 簡易UI（Web）

目的：個人向けに「トークン生成・植え付けテンプレ」を即提供。

- [x] (AI) `public/index.html`（静的）を作る
  - [x] token生成（crypto）
  - [x] `src` のテンプレ入力
  - [x] URLを生成してコピー
  - [x] ファイルトークン（HTML）をその場で生成してDL
- [x] (AI) Admin UI（後回し）
  - [x] まずは export JSON の表示だけ（Access導入後に拡張）

---

## Phase 7: 公開前の最低限ハードニング

- [x] (Human) Cloudflare WAF/RateLimit の実効確認（DoS耐性）
- [x] (Human) `/admin/*` の公開範囲レビュー（Access導入するか）
- [x] (AI) Abuse policy（最小）を README に追記
- [x] (AI) `SECURITY.md`（脆弱性報告窓口）を追加

---

## “AIにやらせる”実務メモ

- AIは「コード/スクリプト/CI」を生成できるが、
  - Token発行（権限付与）
  - Secret投入
  - ドメイン/ゾーン/課金に紐づく操作

は初回は人が介在した方が安全である。
