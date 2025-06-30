# 🔐 مدیریت گواهی SSL/TLS برای Hiddify-Panel با Let's Encrypt (certbot)

یک اسکریپت ساده‌ی Bash برای تولید و نصب گواهی‌های SSL با استفاده از **Certbot** و **Let's Encrypt** برای پنل Hiddify — به عنوان جایگزینی برای `acme.sh` که ممکن است در برخی دامنه‌ها یا زیردامنه‌ها به درستی عمل نکند.

این روش، سازگاری و مدیریت بهتری برای گواهی‌ها فراهم می‌کند، به‌خصوص روی سرورهای مستقل که مستقیماً به دامنه دسترسی دارند.

## 📌 چرا از این روش استفاده کنیم؟

پنل مدیریتی Hiddify به‌صورت پیش‌فرض از [`acme.sh`](https://github.com/acmesh-official/acme.sh) برای صدور گواهی SSL استفاده می‌کند. اما در برخی شرایط، این ابزار ممکن است در اعتبارسنجی یا تمدید گواهی‌ها با مشکل مواجه شود، مخصوصاً برای:

- دامنه‌هایی که پشت Cloudflare Workers قرار دارند
- زیردامنه‌های چندلایه
- سرورهایی با فایروال سفارشی یا تغییرات در پورت‌ها

## 🌟 ویژگی‌های کلیدی

- 🔒 درخواست خودکار گواهی از Let's Encrypt
- 📝 مدیریت ساده دامنه‌ها از طریق منوی تعاملی
- 🛠️ شناسایی و توقف خودکار سرویس‌های استفاده‌کننده از پورت 80
- 🔄 راه‌اندازی مجدد خودکار سرویس‌ها پس از صدور گواهی
- 📊 لاگ کامل عملیات و نمایش دقیق وضعیت
- 📁 سازمان‌دهی خودکار فایل‌های گواهی در مسیر Hiddify
- 🔍 بررسی چندگانه پورت 80 با ابزارهای مختلف

## پیش‌نیازها

- سیستم عامل Linux (Ubuntu/Debian/CentOS)
- دسترسی Root یا sudo
- اتصال اینترنت برای Let's Encrypt
- Git برای دانلود پروژه
- Snap برای نصب Certbot

## 🚀 نصب و راه‌اندازی

### ۱. نصب پیش‌نیازها

```bash
# نصب Git (در صورت عدم وجود)
sudo apt update && sudo apt install git -y

# نصب Snap (در صورت عدم وجود)
sudo apt install snapd -y
```

### ۲. دانلود پروژه با Git Clone

```bash
# کلون کردن مخزن پروژه
git clone https://github.com/ryuk-74/certbot-ssl-for-hiddify.git

# ورود به پوشه پروژه
cd certbot-ssl-for-hiddify

# دادن مجوز اجرا به اسکریپت
chmod +x certbot-for-hiddify.sh
```

### ۳. اجرای اسکریپت

```bash
# اجرا با دسترسی root
sudo ./certbot-for-hiddify.sh
```

## 📱 راهنمای استفاده

اسکریپت دارای منوی تعاملی است که شامل موارد زیر می‌باشد:

### منوی اصلی
```
===== Certbot SSL Manager for Hiddify by Ryuk-74 =====
[*] Configured domains: X

1) Manage Domains
2) Issue Certificates  
3) Install Certbot
4) Exit
```

### مدیریت دامنه‌ها

#### افزودن دامنه جدید
1. از منوی اصلی، گزینه **"Manage Domains"** را انتخاب کنید
2. گزینه **"Add Domain"** را انتخاب کنید
3. دامنه مورد نظر را وارد کنید (مثال: `example.com`)

#### ویرایش دامنه
1. گزینه **"Edit Domain"** را انتخاب کنید
2. شماره دامنه مورد نظر را انتخاب کنید
3. مقدار جدید را وارد کنید

#### حذف دامنه
1. گزینه **"Delete Domain"** را انتخاب کنید
2. شماره دامنه مورد نظر را انتخاب کنید
3. حذف تأیید می‌شود و فایل‌های گواهی مربوطه نیز حذف می‌شوند

### صدور گواهی SSL

#### درخواست گواهی برای تمام دامنه‌ها
```
Issue Certificates → Request All Certificates
```

#### درخواست گواهی برای یک دامنه خاص
```
Issue Certificates → Request for Specific Domain
```

## 🔧 مدیریت خودکار پورت 80

اسکریپت به‌صورت هوشمند پورت 80 را مدیریت می‌کند:

- **شناسایی چندگانه**: از ابزارهای `ss`, `netstat`, `lsof`, و `fuser` استفاده می‌کند
- **توقف سرویس‌ها**: ابتدا سعی در توقف سرویس systemd می‌کند
- **Kill کردن فرآیندها**: در صورت عدم موفقیت، فرآیند را kill می‌کند
- **راه‌اندازی مجدد**: پس از صدور گواهی، سرویس‌ها را مجدداً راه‌اندازی می‌کند

## 📁 ساختار فایل‌ها

```
certbot-ssl-for-hiddify/
├── certbot-for-hiddify.sh          # اسکریپت اصلی
├── domains.txt                     # فایل لیست دامنه‌ها (ایجاد خودکار)
└── README.md

/opt/hiddify-manager/ssl/           # گواهی‌های نهایی (ایجاد خودکار)
├── domain1.com.crt                 # فایل گواهی
├── domain1.com.crt.key            # کلید خصوصی
├── domain2.com.crt
└── domain2.com.crt.key

/etc/letsencrypt/live/             # فایل‌های اصلی Let's Encrypt
```

## 🔍 مدیریت دستی دامنه‌ها

می‌توانید دامنه‌ها را مستقیماً در فایل `domains.txt` نیز مدیریت کنید:

```bash
# افزودن دامنه
echo "example.com" >> domains.txt

# ویرایش فایل
nano domains.txt
```

## 🛠️ عیب‌یابی مشکلات رایج

### خطای "Port 80 in use"
```bash
# بررسی چه سرویسی از پورت 80 استفاده می‌کند
sudo ss -ltnp 'sport = :80'
sudo netstat -tlnp | grep :80
sudo lsof -i :80

# متوقف کردن موقت سرویس مورد نظر
sudo systemctl stop service-name
```

### خطای نصب Certbot
```bash
# نصب دستی Certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
```

### مشکلات دسترسی به فایل
```bash
# بررسی دسترسی‌ها
ls -la /opt/hiddify-manager/ssl/
ls -la /etc/letsencrypt/live/
```

### بررسی وضعیت گواهی
```bash
# بررسی تاریخ انقضای گواهی
sudo certbot certificates

# تست تمدید گواهی
sudo certbot renew --dry-run
```

## 🔄 بروزرسانی اسکریپت

```bash
# ورود به پوشه پروژه
cd certbot-ssl-for-hiddify

# دریافت آخرین نسخه
git pull origin main

# اجرای نسخه جدید
sudo ./certbot-for-hiddify.sh
```

## 🔐 امنیت

- همه فایل‌های کلید خصوصی با دسترسی 600 ذخیره می‌شوند
- فایل‌های گواهی با دسترسی 644 ذخیره می‌شوند
- اسکریپت نیاز به دسترسی root دارد تا بتواند فایل‌ها را در مسیرهای سیستمی کپی کند

## 📝 لاگ‌ها و نظارت

اسکریپت اطلاعات کاملی در مورد عملیات ارائه می‌دهد:
- وضعیت هر مرحله از فرآیند
- جزئیات خطاها
- اطلاعات سرویس‌های متوقف شده
- زمان صدور و مسیر ذخیره گواهی‌ها

---

**⚠️ نکته مهم**: همیشه قبل از اجرا در محیط تولید، اسکریپت را در محیط تست آزمایش کنید.

**🔄 تمدید خودکار**: گواهی‌های Let's Encrypt هر 90 روز انقضا می‌یابند. می‌توانید از cron job برای تمدید خودکار استفاده کنید:

```bash
# افزودن به crontab
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -
```

---

<details>
<summary>💸 حمایت مالی</summary>
  
USDT (TRC20): 
  
  ```
  TCoZp7Zdq34mKuBiDiDR3HLzk92pddTmFr
  ```
</details>
