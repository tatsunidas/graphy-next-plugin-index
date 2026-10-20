## 掲載するプラグイン

- id:
- リポジトリ（公開）: https://github.com/OWNER/REPO

## 確認（すべてにチェックを入れてください）

- [ ] リポジトリは公開で、`LICENSE` があり、ライセンスを明示している
- [ ] 最新の Release（prerelease ではないもの）に、`<id>-<版>.zip`・`.zip.sha256`・`.zip.minisig`・`minisign.pub` の 4 つがある
- [ ] `index.json` の `signerKeyId` は、自分の署名鍵の ID（`minisign.pub` の 1 行目に出る 16 桁）である
- [ ] `plugin.json` の `id` が `index.json` の `id` と同じで、`version` が Release のタグと同じである
- [ ] 秘密鍵を失うと利用者が更新できなくなることを理解している（鍵のバックアップがある）
- [ ] **索引に載ることは安全の保証ではなく、この索引の運営者がプラグインの中身を審査するものではない**ことを理解している
- [ ] [POLICY.md](../POLICY.md) を読み、掲載基準と削除の条件に同意する

機械検査（`Validate index`）が通らない場合は、出力の理由を直してください。
