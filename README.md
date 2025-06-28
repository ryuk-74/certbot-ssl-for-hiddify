# 🔐 تولید گواهی SSL برای Hiddify-Panel با Let's Encrypt (certbot)

یک اسکریپت ساده‌ی Bash برای تولید و نصب گواهی‌های SSL با استفاده از **Certbot** و **Let's Encrypt** برای پنل Hiddify — به عنوان جایگزینی برای `acme.sh` که ممکن است در برخی دامنه‌ها یا زیردامنه‌ها به درستی عمل نکند.

این روش، سازگاری و مدیریت بهتری برای گواهی‌ها فراهم می‌کند، به‌خصوص روی سرورهای مستقل که مستقیماً به دامنه دسترسی دارند.

---

## 📌 چرا از این روش استفاده کنیم؟

پنل مدیریتی Hiddify به‌صورت پیش‌فرض از [`acme.sh`](https://github.com/acmesh-official/acme.sh) برای صدور گواهی SSL استفاده می‌کند. اما در برخی شرایط، این ابزار ممکن است در اعتبارسنجی یا تمدید گواهی‌ها با مشکل مواجه شود، مخصوصاً برای:

- دامنه‌هایی که پشت Cloudflare Workers قرار دارند
- زیردامنه‌های چندلایه
- سرورهایی با فایروال سفارشی یا تغییرات در پورت‌ها

این اسکریپت با استفاده از **Certbot ، جایگزینی پایدار، شفاف و قابل اطمینان ارائه می‌دهد.

---

## ⚙️ پیش‌نیازها

- خاموش بودن فایروال از داخل تنظیمات پنل
- دسترسی root یا sudo
- دامنه‌ها یا زیردامنه‌های شما باید قبلاً به IP سرور اشاره کنند (DNS ست شده باشد)

---

## 🚀 شروع سریع

اسکریپت را دانلود کرده و به‌صورت دستی اجرا کنید:

```bash
curl -o certbot-for-hiddify.sh https://raw.githubusercontent.com/ryuk-74/certbot-ssl-for-hiddify/main/certbot-for-hiddify.sh
chmod +x certbot-for-hiddify.sh
./certbot-for-hiddify.sh
```



<details>
<summary>💸 حمایت مالی</summary>
USDT (TRC20):  
  
```bash
TCoZp7Zdq34mKuBiDiDR3HLzk92pddTmFr 
```
</details>
