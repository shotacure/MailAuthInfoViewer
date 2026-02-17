# Mail Auth Info Viewer

**A Thunderbird add-on to visualize email authentication, sender identity, and delivery routes.**
**メールの認証情報、送信者の身元、および送達経路を可視化するThunderbirdアドオンです。**

Mail Auth Info Viewer is a powerful Thunderbird add-on designed to combat sophisticated phishing and "display name" spoofing. It analyzes message headers locally and presents a clear, color-coded dashboard showing sender alignment, authentication results (SPF, DKIM, DMARC), and delivery routes with time delays directly on the message view.

Mail Auth Info Viewer は、巧妙なフィッシング詐欺や「表示名（名乗り）」の偽装に対抗するために設計された強力なThunderbirdアドオンです。ローカルでメールヘッダを解析し、送信者のアライメント、認証結果（SPF, DKIM, DMARC）、および遅延時間を含む送達経路を、色分けされた分かりやすいダッシュボードでメッセージ画面上に直接表示します。

---

## 📸 Screenshots / スクリーンショット

### Fully Authenticated & Aligned (認証成功・ドメイン一致)
For fully authenticated and safe emails, the dashboard automatically collapses to save screen space while keeping the top status badge visible.  
安全な認証済みメールの場合、画面スペースを節約するためにダッシュボードは自動的に折りたたまれます（上部のステータスバッジのみ表示）。
![Verified Mail (Collapsed)](images/ss_verified.png)
![Verified Mail (Collapsed)](images/ss_verified_open.png)

### Unverified & Delayed Routing (未認証・遅延発生の警告)
![Unverified Mail](images/ss_unverified.png)

---

## 🌟 Key Features / 主な機能

* **Smart Auto-Collapse:** The dashboard stays neatly collapsed for safe, authenticated emails to maximize your reading space. It automatically expands with a smooth animation only when an unverified sender or a domain mismatch is detected.
    * **スマート自動折りたたみ:** 安全な認証済みメールではダッシュボードが自動で折りたたまれ、メール本文の閲覧スペースを広く保ちます。未認証やドメイン不一致を検知した「要確認」のメールの場合のみ、自動的にスライド展開して警告します。
* **Sender Identity & Alignment:** Instantly spot discrepancies between the Display Name, Header From, and Envelope From addresses side-by-side.
    * **送信者の身元とアライメント検証:** 「表示名」「ヘッダFrom」「エンベロープFrom」を並べて表示し、アドレスの不自然な乖離や偽装を瞬時に見抜きます。
* **Domain Verification Badge:** Prominently displays the actual authenticated domain (e.g., `✅ AUTH PASS example.com`) to prevent false trust in fake display names.
    * **ドメイン認証バッジ:** 単なる「認証済」ではなく、実際に認証されたドメイン名を明記し、誤った安心感を与えません。
* **Authentication Status:** Quickly check the pass/fail status of SPF, DKIM, and DMARC authentication.
    * **認証ステータス:** SPF、DKIM、DMARC認証の成功/失敗ステータスを素早く確認できます。
* **Delivery Route Visualization:** View the email's path from the sender (ORIGIN) to your inbox, including calculated time delays between each hop. Long delays are highlighted in red/orange.
    * **送達経路の可視化:** 送信元（ORIGIN）から受信ボックスまでのメールの経路を、各ホップ間の遅延時間とともに表示します。大きな遅延は赤やオレンジで強調されます。
* **Privacy First:** All processing is performed strictly locally within Thunderbird. No external network requests are made.
    * **プライバシー重視:** すべての解析処理はThunderbird内でローカルに完結します。外部ネットワークへの通信は一切行いません。

## 🚀 How to Use / 使い方

After installing the add-on, simply open any email in Thunderbird. A new information panel will appear at the top of the message view.

アドオンをインストールした後、Thunderbirdでメールを開くだけです。メッセージ表示画面の上部に新しい情報パネルが表示されます。

* **Overall Status:** A large badge indicates the verified domain or issues (e.g., `✅ AUTH PASS`, `❌ AUTH FAILED`, `⚠️ AUTH PASS (DOMAIN MISMATCH)`, `UNVERIFIED`).
    * **総合ステータス:** 大きなバッジが認証されたドメインや問題を警告します。
* **Manual Toggle:** You can click the header bar at any time to expand or collapse the detailed view.
    * **手動開閉:** ヘッダーバーをクリックすることで、いつでも詳細ビューの展開・折りたたみを切り替えられます。
* **Address & Alignment:** Highlights the sender's addresses. If the domain doesn't match the authenticated envelope, it alerts you to potential spoofing or mailing list routing.
    * **アドレスとアライメント:** 送信者のアドレスを強調表示します。ドメインがエンベロープと一致しない場合、なりすましやメーリングリスト経由の可能性を警告します。
* **Delivery Route:** The table at the bottom shows the path. The first row ("ORIGIN 🚀") is the sender. The time difference between each hop is shown on the left.
    * **送達経路:** 下部のテーブルが経路を示します。最初の行（"ORIGIN 🚀"）が送信元です。各ホップ間の時間差が左側に表示されます。

## 📥 Installation / インストール

[**Download from ATN (Thunderbird Add-ons)**](https://addons.thunderbird.net/ja/thunderbird/addon/mail-auth-info-viewer/)

You can also download the latest release directly from GitHub:  
GitHubのReleasesからも最新版をダウンロードできます:  
[**GitHub Releases**](https://github.com/shotacure/MailAuthInfoViewer/releases)

---

## 📝 License / ライセンス

This project is licensed under the GNU General Public License v3.0 (GPLv3).
このプロジェクトは、GNU General Public License v3.0 (GPLv3) の下でライセンスされています。

See the [LICENSE](LICENSE) file for details.  
詳細は [LICENSE](LICENSE) ファイルをご覧ください。