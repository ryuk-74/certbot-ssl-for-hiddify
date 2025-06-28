# 🔐 مدیریت گواهی SSL/TLS برای Hiddify-Panel با Let's Encrypt (certbot)

یک اسکریپت ساده‌ی Bash برای تولید و نصب گواهی‌های SSL با استفاده از **Certbot** و **Let's Encrypt** برای پنل Hiddify — به عنوان جایگزینی برای `acme.sh` که ممکن است در برخی دامنه‌ها یا زیردامنه‌ها به درستی عمل نکند.

این روش، سازگاری و مدیریت بهتری برای گواهی‌ها فراهم می‌کند، به‌خصوص روی سرورهای مستقل که مستقیماً به دامنه دسترسی دارند.

## 📌 چرا از این روش استفاده کنیم؟

پنل مدیریتی Hiddify به‌صورت پیش‌فرض از [`acme.sh`](https://github.com/acmesh-official/acme.sh) برای صدور گواهی SSL استفاده می‌کند. اما در برخی شرایط، این ابزار ممکن است در اعتبارسنجی یا تمدید گواهی‌ها با مشکل مواجه شود، مخصوصاً برای:

- دامنه‌هایی که پشت Cloudflare Workers قرار دارند
- زیردامنه‌های چندلایه
- سرورهایی با فایروال سفارشی یا تغییرات در پورت‌ها

## ویژگی‌های کلیدی

- 🔒 درخواست خودکار گواهی از Let's Encrypt
- 📝 مدیریت ساده دامنه‌ها از طریق فایل متنی
- 🔄 پشتیبانی از روش‌های مختلف تأیید (Standalone, DNS, Webroot)
- 📊 لاگ کامل عملیات
- 📁 سازمان‌دهی خودکار فایل‌های گواهی

## پیش‌نیازها

- سیستم عامل Linux (Ubuntu/Debian/CentOS)
- دسترسی Root یا sudo
- اتصال اینترنت برای Let's Encrypt
- پورت 80 آزاد (در صورت استفاده از روش Standalone)

## نصب و راه‌اندازی

### 1. دانلود اسکریپت

```bash
curl -o certbot-for-hiddify.sh https://raw.githubusercontent.com/ryuk-74/certbot-ssl-for-hiddify/main/certbot-for-hiddify.sh
chmod +x certbot-for-hiddify.sh
```

### 2. اجرای اسکریپت

```bash
./certbot-for-hiddify.sh
```

## راهنمای استفاده

### مدیریت دامنه‌ها

#### افزودن دامنه جدید
1. از منوی اصلی، گزینه "Manage Domains" را انتخاب کنید
2. گزینه "Add Domain" را انتخاب کنید
3. دامنه مورد نظر را وارد کنید (مثال: `example.com`)

#### ویرایش دامنه
1. گزینه "Edit Domain" را انتخاب کنید
2. شماره دامنه مورد نظر را انتخاب کنید
3. مقدار جدید را وارد کنید

#### حذف دامنه
1. گزینه "Delete Domain" را انتخاب کنید
2. شماره دامنه مورد نظر را انتخاب کنید
3. حذف را تأیید کنید

### درخواست گواهی SSL

#### درخواست گواهی برای تمام دامنه‌ها
```
Certificate Operations → Request All Certificates
```

#### درخواست گواهی برای یک دامنه
```
Certificate Operations → Request Single Certificate
```

### روش‌های تأیید دامنه

#### 1. Standalone (پیشنهادی برای سرورهای ساده)
- **پیش‌نیاز**: پورت 80 باید آزاد باشد
- **مناسب برای**: سرورهایی که وب‌سرور ندارند یا می‌توان آن را موقتاً متوقف کرد

```bash
# بررسی وضعیت پورت 80
sudo netstat -tlnp | grep :80
```

#### 2. DNS Challenge (پیشنهادی برای محیط‌های پیچیده)
- **مزایا**: نیازی به پورت 80 نیست
- **نیاز**: دسترسی به تنظیمات DNS دامنه
- **فرآیند**: 
  1. اسکریپت یک رکورد TXT ارائه می‌دهد
  2. این رکورد را در DNS دامنه اضافه کنید
  3. Enter را فشار دهید تا ادامه یابد

#### 3. Webroot (برای وب‌سرورهای فعال)
- **پیش‌نیاز**: وب‌سرور در حال اجرا (Apache/Nginx)
- **نیاز**: مسیر webroot (معمولاً `/var/www/html`)

## ساختار فایل‌ها

```
/opt/hiddify-manager/ssl/    # گواهی‌های نهایی
├── domain1.com.crt          # فایل گواهی
├── domain1.com.crt.key      # کلید خصوصی
├── domain2.com.crt
└── domain2.com.crt.key

/etc/letsencrypt/live/       # فایل‌های اصلی Let's Encrypt
domains.txt                  # لیست دامنه‌ها
/var/log/ssl-cert-manager.log # فایل لاگ
```
## مدیریت فایل domains.txt

می‌توانید دامنه‌ها را مستقیماً در فایل `domains.txt` اضافه کنید:

```bash
echo "example.com" >> domains.txt
echo "subdomain.example.com" >> domains.txt
```
## عیب‌یابی مشکلات رایج

### خطای "Port 80 in use"
```bash
# بررسی چه سرویسی از پورت 80 استفاده می‌کند
sudo lsof -i :80

# متوقف کردن موقت سرویس 
sudo systemctl stop servicename

```

### خطای DNS در روش Manual
- اطمینان حاصل کنید رکورد TXT به درستی اضافه شده
- منتظر انتشار DNS بمانید (تا 10 دقیقه)
- از ابزارهای آنلاین DNS برای بررسی استفاده کنید

---


**نکته**: همیشه قبل از اجرا در محیط تولید، اسکریپت را در محیط تست آزمایش کنید.






---

<details>
<summary>💸 حمایت مالی</summary>
USDT (TRC20): 
  
  ```
  TCoZp7Zdq34mKuBiDiDR3HLzk92pddTmFr
  ```
</details>
