# graphy-next-plugin-index

GRAPHY-Next の環境設定＞プラグイン「見つける」に表示する、プラグインの索引（`index.json`）です。

- 掲載は「見つけやすくするため」のものです。**掲載は安全の保証ではありません。** 導入時は本体が署名を検証し、同意画面を出します。
- 「公式」の表示は、この索引の記述ではなく、導入前の検査で公式鍵の署名が通ったかどうかで決まります。
- 現在の掲載は当社の公式プラグインのみです。第三者プラグインの掲載手順は、準備でき次第ここに追記します。

## 形式
```json
{ "plugins": [ { "id": "", "name": "", "repo": "owner/repo", "description": "", "category": "ai",
                 "signerKeyId": "16 桁の minisign 鍵 ID（任意）", "minGraphy": "必要な本体の最小版（任意）" } ] }
```

## 掲載の申請

1. プラグインを公開リポジトリで作り、署名つきの Release を出す（[テンプレート](https://github.com/tatsunidas/graphy-next-plugin-template) の README を参照）。
2. このリポジトリを fork し、`index.json` の `plugins` に 1 行足す Pull Request を出す（`signerKeyId` は必須）。
3. 機械検査（`Validate index`）が通ることを確認する。通らなければ、出力の理由を直す。
4. 運営者が確認してマージすると、GRAPHY-Next の「見つける」に出る。

[POLICY.md](POLICY.md)（下書き）も参照してください。

### 機械検査

`scripts/validate.py` が、形式（本体と同じ規則に加え `signerKeyId` を必須）と、最新リリースの完全性・`plugin.json`・署名を検査します。
ここを通っても、**プラグインの中身の安全は確認していません。** 申請の PR のコードは実行せず、`index.json` をデータとして読むだけです。
週に 1 回、掲載済みの全行を点検し、リリースが消えた・署名が壊れた行を見つけます（自動では削除しません）。

手元で確認するには（Python 3 と minisign が要ります）:

```bash
python3 -I scripts/test_validate.py   # 検査自体の試験（使い捨ての鍵で組み立てるのでネットワーク不要）
python3 -I scripts/validate.py        # 現在の index.json の全行を、実際の Release で検査
```
