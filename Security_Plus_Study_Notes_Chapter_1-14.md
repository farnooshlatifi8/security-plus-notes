# یادداشت‌های مطالعه CompTIA Security+

> خلاصه و نکات کلیدی برای مرور سریع مباحث امنیت سایبری و آمادگی آزمون  
> **منبع پایه:** کتاب راهنمای مطالعه CompTIA Security+  
>
> این فایل بازنویسی و مرتب‌سازی شده است تا مفاهیم با ساختار منظم‌تر و خوانایی بهتر در GitHub قابل مطالعه باشند.

---

## فهرست مطالب

1. [مدیریت ریسک](#1-مدیریت-ریسک)
2. [مانیتورینگ و تشخیص شبکه](#2-مانیتورینگ-و-تشخیص-شبکه)
3. [شبکه، احراز هویت و کنترل دسترسی](#3-شبکه-احراز-هویت-و-کنترل-دسترسی)
4. [Wireless و فناوری‌های ارتباطی](#4-wireless-و-فناوریهای-ارتباطی)
5. [Cloud و Virtualization](#5-cloud-و-virtualization)
6. [Malware و حملات](#6-malware-و-حملات)
7. [Social Engineering و کنترل‌های امنیتی](#7-social-engineering-و-کنترلهای-امنیتی)
8. [امنیت فیزیکی و محیطی](#8-امنیت-فیزیکی-و-محیطی)
9. [رمزنگاری و مفاهیم مرتبط](#9-رمزنگاری-و-مفاهیم-مرتبط)
10. [Incident Response و Disaster Recovery](#10-incident-response-و-disaster-recovery)
11. [Recon و Penetration Testing](#11-recon-و-penetration-testing)
12. [Backup، Site و Failover](#12-backup-site-و-failover)
13. [مرور شب امتحانی](#13-مرور-شب-امتحانی)

---

# 1. مدیریت ریسک

## 1.1 اصطلاحات پایه ریسک

| اصطلاح | معنی ساده |
|---|---|
| **Risk** | احتمال وقوع یک تهدید و تأثیر ناشی از آن |
| **Vulnerability** | نقص یا نقطه‌ضعفی در رویه، طراحی یا پیاده‌سازی که می‌تواند مورد سوءاستفاده قرار گیرد |
| **Threat** | هر عامل داخلی یا خارجی که پتانسیل آسیب‌زدن به منابع را داشته باشد |

## 1.2 محاسبات کمی ریسک

برای ارزیابی مالی ریسک، سه مفهوم مهم را باید به خاطر سپرد:

- **SLE (Single Loss Expectancy):** خسارت مورد انتظار از یک رخداد  
  `SLE = Asset Value (AV) × Exposure Factor (EF)`
- **ARO (Annualized Rate of Occurrence):** تعداد دفعاتی که انتظار می‌رود یک تهدید در سال رخ دهد.  
  مثال: اگر رخداد به‌طور متوسط هر ۵ سال یک‌بار اتفاق بیفتد، ARO برابر `0.2` است.
- **ALE (Annualized Loss Expectancy):** خسارت مورد انتظار سالانه  
  `ALE = SLE × ARO`

## 1.3 استراتژی‌های پاسخ به ریسک

چهار روش اصلی:

1. **Avoidance — اجتناب:** فعالیتی را که باعث ایجاد ریسک می‌شود متوقف می‌کنیم.
2. **Transference — انتقال:** بخشی از بار ریسک را به شخص ثالث منتقل یا با او به اشتراک می‌گذاریم؛ مثل بیمه یا برخی خدمات ابری.
3. **Mitigation — کاهش:** احتمال وقوع یا شدت اثر ریسک را کم می‌کنیم؛ مثل فایروال یا آنتی‌ویروس.
4. **Acceptance — پذیرش:** وقتی هزینه مقابله با ریسک بیشتر از خسارت احتمالی باشد، ریسک را می‌پذیریم.

## 1.4 BIA و تداوم فعالیت

- **BIA (Business Impact Analysis):** بررسی تأثیر اختلال‌ها و حوادث بر کسب‌وکار.
- **RTO (Recovery Time Objective):** حداکثر زمانی که یک سرویس می‌تواند قطع باشد.
- **RPO (Recovery Point Objective):** مشخص می‌کند داده‌ها باید تا چه نقطه‌ای بازیابی شوند و سازمان چه میزان از دست‌رفتن داده را تحمل می‌کند.
- **MTBF (Mean Time Between Failures):** میانگین زمان بین خرابی‌ها و شاخصی برای طول عمر/قابلیت اطمینان پیش‌بینی‌شده سیستم.

## 1.5 مدیریت پرسنل و دسترسی

- **Mandatory Vacations:** مرخصی اجباری برای کمک به شناسایی تقلب و کاهش وابستگی سازمان به یک فرد.
- **Job Rotation:** چرخش شغلی برای جلوگیری از وابستگی به یک نفر و ایجاد افزونگی مهارت‌ها.
- **Separation of Duties:** تقسیم وظایف حساس بین چند نفر برای کاهش احتمال تبانی و سوءاستفاده.
- **Least Privilege:** هر کاربر فقط حداقل سطح دسترسی موردنیاز برای انجام وظایف خود را داشته باشد.

## 1.6 سیاست‌ها و توافق‌نامه‌ها

| مفهوم | معنی |
|---|---|
| **Policy** | راهنمای سطح‌بالا درباره اهداف و الزامات سازمان |
| **Standard** | الزام مشخص و اجباری درباره چیزی که باید رعایت شود |
| **Guideline** | توصیه‌ای برای نحوه انجام کار که معمولاً اجباری نیست |
| **SLA** | توافق‌نامه‌ای که سطح و الزامات خدمات ارائه‌شده توسط فروشنده را مشخص می‌کند |

## 1.7 RAID

| RAID | روش | نکته |
|---|---|---|
| **RAID 0** | Striping | افزایش سرعت، بدون تحمل خطا |
| **RAID 1** | Mirroring | کپی داده روی دو دیسک و افزونگی بالا |
| **RAID 5** | Striping + Parity | حداقل ۳ دیسک؛ تحمل خرابی یک دیسک |

---

# 2. مانیتورینگ و تشخیص شبکه

## 2.1 چارچوب‌ها و استانداردها

### ISO

- **ISO 27001:** پیاده‌سازی سیستم مدیریت امنیت اطلاعات (**ISMS**)
- **ISO 27002:** بهترین روش‌ها و کنترل‌های امنیتی
- **ISO 27017:** امنیت در محیط Cloud
- **ISO 27018:** حریم خصوصی و حفاظت از PII در Cloud

### NIST

- **NIST 800-30:** راهنمای ارزیابی ریسک
- **NIST 800-53:** کنترل‌های امنیتی و حریم خصوصی

### استانداردهای صنعتی

- **PCI DSS:** برای محیط‌ها و سازمان‌هایی که با داده‌های کارت پرداخت سروکار دارند.
- **OWASP:** مرجع مهم امنیت اپلیکیشن‌های وب و شناسایی آسیب‌پذیری‌های رایج.

## 2.2 معماری شبکه امن

- **Zones:** تقسیم شبکه به مناطق مختلف بر اساس سطح حساسیت و امنیت.
- **DMZ:** منطقه‌ای برای قرار دادن سرویس‌های عمومی مانند Web Server، به‌گونه‌ای که دسترسی مستقیم از اینترنت به شبکه داخلی محدود شود.
- **Segmentation:** جداسازی منطقی یا فیزیکی بخش‌های شبکه، مثلاً با VLAN یا Router.
- **Defense in Depth:** استفاده از چندین لایه دفاعی به‌جای تکیه بر یک کنترل امنیتی.
- **Air Gap:** جداسازی کامل یک سیستم حساس از شبکه‌های فیزیکی یا بی‌سیم.

## 2.3 تجهیزات و فناوری‌های امنیتی

- **Packet-Filtering Firewall:** فیلترکردن ترافیک بر اساس مواردی مانند IP و Port.
- **Proxy Firewall:** قرارگرفتن واسطه بین شبکه داخلی و خارجی.
- **SPI:** بررسی وضعیت و State ارتباطات.
- **Honeypot:** سیستم جعلی برای جذب مهاجم و مطالعه رفتار او.
- **Honeynet:** شبکه‌ای از سیستم‌های جعلی برای جذب و مطالعه مهاجمان.
- **VPN:** ایجاد تونل امن و رمزنگاری‌شده روی شبکه ناامن.
- **IDS:** تشخیص و گزارش فعالیت مشکوک.
- **IPS:** تشخیص فعالیت مشکوک و جلوگیری از آن.

## 2.4 Hardening

**Hardening** یعنی مقاوم‌سازی سیستم قبل از قرارگرفتن در معرض تهدید.

### Hardware Hardening
- استفاده از **TPM** برای نگهداری امن کلیدهای رمزنگاری.
- استفاده از **Secure Boot** برای اطمینان از صحت اجزای فرایند Boot.

### OS Hardening
- غیرفعال‌کردن Port و Serviceهای غیرضروری.
- حذف حساب‌های پیش‌فرض غیرضروری.
- حذف نرم‌افزارهای غیرضروری.
- استفاده از **Whitelisting** در صورت نیاز.

### Patch Management
- تست Patchها در محیط آزمایشگاهی.
- سپس نصب در محیط Production.
- داشتن **Backout Plan** در صورت بروز مشکل.

## 2.5 محیط‌های استقرار و تست

ترتیب معمول استقرار:

**Development → Test → Staging → Production**

- **Sandbox:** محیطی ایزوله برای اجرای برنامه‌ها یا کدهای مشکوک بدون آسیب‌زدن به شبکه اصلی.

---

# 3. شبکه، احراز هویت و کنترل دسترسی

## 3.1 تجهیزات و مفاهیم شبکه

| ابزار/مفهوم | کاربرد |
|---|---|
| **Router** | Routing و کار با IP |
| **Switch** | اتصال دستگاه‌ها در شبکه و استفاده از MAC |
| **Bridge** | اتصال/تفکیک Segmentها در Layer 2 |
| **STP** | جلوگیری از Loop در شبکه |
| **Load Balancer** | توزیع بار بین چند سیستم |
| **Round-Robin** | توزیع نوبتی درخواست‌ها |
| **Active-Active** | چند سیستم به‌طور همزمان Active هستند |
| **WORM** | Write Once, Read Many |
| **TPM** | تراشه امنیتی |
| **HSM** | سخت‌افزار تخصصی برای عملیات و نگهداری امن کلیدهای رمزنگاری |

## 3.2 ابزارهای مهم خط فرمان

| دستور | سؤال کلیدی که پاسخ می‌دهد |
|---|---|
| `ipconfig` | IP و تنظیمات شبکه من چیست؟ |
| `ping` | آیا مقصد قابل دسترسی است؟ |
| `arp -a` | کدام MAC به کدام IP مربوط است؟ |
| `netstat` | چه Connection و Portهایی فعال هستند؟ |
| `nslookup` | DNS چه IP/Domainای را نشان می‌دهد؟ |
| `tracert` | مسیر رسیدن به مقصد از چه Hopهایی عبور می‌کند؟ |

## 3.3 چرخه هویت و دسترسی

- **Identification:** ادعای هویت؛ «من چه کسی هستم؟»
- **Authentication:** اثبات هویت؛ «چطور ثابت کنم همان فرد هستم؟»
- **Authorization:** تعیین مجوزها؛ «چه کاری اجازه دارم انجام دهم؟»
- **Accounting:** ثبت فعالیت‌ها؛ «چه کاری انجام داده‌ام؟»

### Authentication Factors

- **Something You Know:** Password / PIN
- **Something You Have:** Phone / Token
- **Something You Are:** Fingerprint / Biometrics
- **Somewhere You Are:** Location

## 3.4 سرویس‌های احراز هویت

- **LDAP:** سرویس Directory
- **Kerberos:** احراز هویت مبتنی بر Ticket
- **RADIUS:** احراز هویت متمرکز برای دسترسی شبکه
- **TACACS+:** احراز هویت و مدیریت دسترسی برای تجهیزات شبکه و مدیران
- **SAML:** احراز هویت و SSO در محیط‌های Web
- **KDC:** جزء مرکزی در Kerberos برای مدیریت Ticketها

## 3.5 مدل‌های کنترل دسترسی

| مدل | چه کسی تصمیم می‌گیرد؟ |
|---|---|
| **MAC** | سیستم/Policy |
| **DAC** | مالک Resource |
| **RBAC** | Role |
| **Rule-Based** | Ruleهای تعریف‌شده |
| **ABAC** | Attributes و شرایط |

**Least Privilege:** فقط مجوزهای لازم را اختصاص بده.

---

# 4. Wireless و فناوری‌های ارتباطی

| مفهوم | معنی |
|---|---|
| **SSID** | نام شبکه Wi-Fi |
| **AP** | Access Point |
| **WPS** | ساده‌سازی اتصال به Wi-Fi |
| **802.1X** | کنترل دسترسی به شبکه |
| **SSID Cloaking** | مخفی‌کردن Broadcast نام شبکه |
| **Wireless Site Survey** | بررسی و تحلیل محیط Wireless |
| **WEP** | استاندارد قدیمی و ناامن |
| **WPA2/AES** | امنیت قوی‌تر و استانداردتر نسبت به WEP/TKIP |
| **TKIP** | روش قدیمی‌تر و ضعیف‌تر |
| **Replay Attack** | Capture و ارسال مجدد داده |
| **Evil Twin** | AP جعلی با SSID مشابه شبکه واقعی |
| **Rogue AP** | Access Point غیرمجاز در شبکه |
| **Jamming** | ایجاد نویز برای اختلال ارتباط |
| **Disassociation** | قطع اجباری اتصال Client |
| **Bluejacking** | ارسال پیام ناخواسته از طریق Bluetooth |
| **Bluesnarfing** | سرقت اطلاعات از طریق Bluetooth |
| **RFID** | شناسایی با امواج رادیویی |
| **NFC** | ارتباط در فاصله بسیار نزدیک |

---

# 5. Cloud و Virtualization

## 5.1 مدل‌های سرویس Cloud

| مدل | مفهوم ساده |
|---|---|
| **SaaS** | استفاده از نرم‌افزار آماده |
| **PaaS** | اجرای/ساخت Application روی Platform |
| **IaaS** | دریافت زیرساخت با کنترل بیشتر |

## 5.2 مدل‌های Deployment

| مدل | مفهوم |
|---|---|
| **Public Cloud** | زیرساخت عمومی و چندمشتری |
| **Private Cloud** | مخصوص یک سازمان |
| **Community Cloud** | چند سازمان با نیاز مشترک |
| **Hybrid Cloud** | ترکیب چند مدل Cloud |

## 5.3 Virtualization

- **Virtualization:** اجرای چند سیستم مجازی روی یک Hardware.
- **Hypervisor:** مدیریت VMها.
- **Type I — Bare Metal:** مستقیماً روی Hardware اجرا می‌شود.
- **Type II — Hosted:** روی یک Operating System اجرا می‌شود.
- **Host:** سیستم میزبان.
- **Guest:** ماشین مجازی.

## 5.4 مفاهیم مهم Virtualization و Cloud

- **VM Escape:** خروج VM از محیط ایزوله خود.
- **VM Sprawl:** افزایش تعداد VMها بدون مدیریت و کنترل مناسب.
- **Multitenancy:** استفاده چند مشتری از یک زیرساخت مشترک.
- **CASB:** واسطه امنیتی برای اعمال سیاست‌های امنیتی بین کاربر و Cloud.
- **Elasticity:** افزایش یا کاهش سریع منابع متناسب با نیاز.
- **Measured Service:** اندازه‌گیری مصرف منابع/خدمات.
- **On-Demand:** دریافت منابع هنگام نیاز.
- **Cloud Bursting:** انتقال بار اضافی به Cloud هنگام افزایش تقاضا.
- **Sandbox:** محیط محدود و ایزوله.

---

# 6. Malware و حملات

## 6.1 انواع Malware

| Malware | مفهوم |
|---|---|
| **Virus** | آلوده‌کردن فایل یا برنامه و وابستگی به اجرای آن |
| **Worm** | تکثیر خودکار و انتشار بدون نیاز به وابستگی مستقیم به فایل میزبان |
| **Trojan** | برنامه‌ای که ظاهراً مفید است اما رفتار مخرب دارد |
| **Ransomware** | رمزگذاری داده‌ها و درخواست باج |
| **Rootkit** | مخفی‌کاری و پنهان‌کردن حضور مهاجم/بدافزار |
| **Keylogger** | ثبت کلیدهای فشرده‌شده توسط کاربر |
| **Zombie** | سیستم آلوده‌ای که تحت کنترل مهاجم قرار گرفته و می‌تواند عضو Botnet باشد |

## 6.2 حملات مهم

| حمله | مفهوم ساده |
|---|---|
| **DoS** | ایجاد اختلال در Availability یک سرویس |
| **DDoS** | حمله DoS از چندین سیستم |
| **MITM** | قرارگرفتن مهاجم در میان ارتباط دو طرف |
| **MITB** | دستکاری تراکنش‌ها در مرورگر |
| **Buffer Overflow** | نوشتن داده بیشتر از ظرفیت Buffer |
| **SQL Injection** | تزریق ورودی مخرب برای اثرگذاری بر Database |
| **LDAP Injection** | تزریق ورودی مخرب به Queryهای LDAP |
| **XSS** | اجرای Script مخرب در زمینه مرورگر قربانی |
| **CSRF/XSRF** | وادارکردن کاربر به ارسال درخواست ناخواسته |
| **ARP Poisoning** | دستکاری نگاشت IP به MAC |
| **DNS Poisoning** | دستکاری نگاشت Domain به IP |
| **Spoofing** | جعل هویت، آدرس یا منبع |
| **Replay** | Capture و ارسال مجدد داده معتبر |
| **Clickjacking** | فریب کاربر برای کلیک روی عنصر ناخواسته |
| **Session Hijacking** | سرقت و استفاده از Session قربانی |
| **Typosquatting** | استفاده از Domain مشابه با نام واقعی |
| **Zero-Day** | آسیب‌پذیری‌ای که هنوز Patch یا دفاع مؤثر شناخته‌شده‌ای برای آن وجود ندارد |

---

# 7. Social Engineering و کنترل‌های امنیتی

## 7.1 Social Engineering

**Social Engineering** یعنی حمله به انسان به‌جای تمرکز مستقیم روی سیستم.

| حمله | روش |
|---|---|
| **Phishing** | پیام/ایمیل فریبنده |
| **Vishing** | حمله از طریق Voice/تماس |
| **Smishing** | حمله از طریق SMS |
| **Whaling** | هدف‌گرفتن افراد مهم یا مدیران |
| **Tailgating** | واردشدن به محیط مجاز با پشت سر فرد مجاز واردشدن |
| **Shoulder Surfing** | مشاهده صفحه، Keyboard یا اطلاعات قربانی از پشت سر |
| **Dumpster Diving** | جست‌وجوی اطلاعات در زباله‌ها |
| **Watering Hole** | آلوده‌کردن سایتی که قربانیان هدف معمولاً از آن بازدید می‌کنند |
| **Mantrap** | فضای دارای دو در برای کنترل ورود و خروج |

## 7.2 انواع Security Control

| Control | مفهوم | مثال |
|---|---|---|
| **Deterrent** | بازدارنده | تابلو هشدار |
| **Preventive** | جلوگیری‌کننده | قفل در |
| **Detective** | تشخیص‌دهنده | Alarm / Sensor |
| **Corrective** | اصلاح‌کننده | اقدام برای اصلاح وضعیت |
| **Compensating** | جبرانی/جایگزین | کنترل جایگزین |
| **Technical** | فنی | Firewall |
| **Administrative** | مدیریتی | Policy |
| **Awareness** | آگاهی‌رسانی | آموزش کاربر |
| **Environmental** | محیطی | کنترل دما، رطوبت، آتش و برق |

---

# 8. امنیت فیزیکی و محیطی

- **Biometrics:** استفاده از ویژگی فیزیکی/زیستی برای شناسایی.
- **Fence:** کنترل امنیتی پیرامونی (**Perimeter Security**).
- **Shielding:** کاهش اثر **EMI/RFI**.
- **RFI:** تداخل در طیف فرکانس رادیویی.
- **Desensitization:** کاهش حساسیت گیرنده در اثر سیگنال RF قوی.

## Fire Classes

| Class | نوع |
|---|---|
| **Class A** | آتش‌های معمولی |
| **Class B** | مایعات قابل اشتعال |
| **Class C** | تجهیزات/منابع الکتریکی |
| **Class K** | روغن‌های آشپزی |

### Fire Suppression

- **Portable Fire Extinguisher:** کپسول آتش‌نشانی قابل حمل.
- **Fixed Fire Suppression:** سیستم ثابت اطفای حریق.
- **Gas Suppression:** مناسب تجهیزات حساس و محیط‌های کنترل‌شده.

---

# 9. رمزنگاری و مفاهیم مرتبط

| مفهوم | نکته کلیدی |
|---|---|
| **AES** | الگوریتم رمزنگاری Symmetric |
| **RSA** | الگوریتم Asymmetric |
| **DH (Diffie-Hellman)** | Key Exchange |
| **SHA** | Hash |
| **Hash** | بررسی Integrity |
| **Digital Signature** | Integrity + Nonrepudiation |
| **CA** | صادرکننده Certificate |
| **CRL** | فهرست Certificateهای Revoked |
| **OCSP** | بررسی وضعیت Certificate به‌صورت Online |

---

# 10. Incident Response و Disaster Recovery

## 10.1 Incident Response

مراحل اصلی:

1. **Preparation:** آماده‌سازی
2. **Identification:** شناسایی حادثه
3. **Containment:** محدودکردن و کنترل حادثه
4. **Eradication:** حذف کامل تهدید
5. **Recovery:** بازگرداندن سیستم به وضعیت عملیاتی
6. **Lessons Learned:** بررسی حادثه و یادگیری برای جلوگیری از تکرار

### تفاوت‌های مهم

- **Incident Response:** مدیریت و پاسخ به حادثه امنیتی.
- **Disaster Recovery:** بازگرداندن سیستم‌ها و خدمات پس از خرابی یا Disaster.
- **Business Continuity:** ادامه فعالیت کسب‌وکار در زمان بحران.

---

# 11. Recon و Penetration Testing

## 11.1 Recon

- **Passive Recon:** جمع‌آوری اطلاعات بدون تعامل مستقیم با Target.
- **Active Recon:** جمع‌آوری اطلاعات با تعامل مستقیم با Target.

## 11.2 مدل‌های Penetration Testing

| مدل | میزان اطلاعات تستر |
|---|---|
| **Black Box** | اطلاعات اولیه یا بسیار محدود |
| **Gray Box** | اطلاعات محدود |
| **White Box** | اطلاعات کامل |

## 11.3 مفاهیم مهم

- **Pivoting:** حرکت از سیستم هک‌شده به سمت سیستم یا شبکه دیگر.
- **Persistence:** حفظ دسترسی پس از نفوذ.
- **RAM:** داده‌های با فراریت بالا که ممکن است پس از خاموش‌شدن سیستم از بین بروند.
- **Evidence:** شواهد دیجیتال.
- **Chain of Custody:** ثبت و حفظ زنجیره نگهداری شواهد.
- **Legal Hold:** حفظ اطلاعات برای امور حقوقی.

---

# 12. Backup، Site و Failover

## 12.1 Backup

| نوع Backup | چه چیزی را Backup می‌کند؟ |
|---|---|
| **Full** | همه داده‌ها |
| **Incremental** | تغییرات از آخرین Backup |
| **Differential** | تغییرات از آخرین Full Backup |

### یک نکته مهم برای حفظ کردن

- **Incremental:** از آخرین Backup
- **Differential:** از آخرین Full

## 12.2 Recovery Site

| Site | سرعت بازیابی |
|---|---|
| **Hot Site** | سریع‌ترین |
| **Warm Site** | متوسط |
| **Cold Site** | کندترین |

## 12.3 Failover

**Failover** یعنی انتقال سرویس یا عملیات به یک سیستم جایگزین در صورت خرابی سیستم اصلی.

## 12.4 Tabletop Exercise

**Tabletop Exercise** یک تمرین سناریومحور است که در آن اعضای تیم دور یک میز سناریوی بحران را بررسی و درباره واکنش مناسب گفت‌وگو می‌کنند.

---

# 13. مرور شب امتحانی ⭐

اگر زمان خیلی کمی داری، این تطبیق‌ها را اول مرور کن:

### Risk
- `Risk` → احتمال + اثر تهدید
- `Vulnerability` → ضعف قابل سوءاستفاده
- `Threat` → عامل بالقوه آسیب
- `SLE` → خسارت یک رخداد
- `ALE` → خسارت سالانه
- `ARO` → نرخ وقوع سالانه
- `RTO` → حداکثر زمان قابل‌تحمل برای Downtime
- `RPO` → میزان/نقطه داده قابل‌تحمل برای از دست‌رفتن
- `Avoid / Transfer / Mitigate / Accept` → چهار پاسخ به ریسک

### Network Security
- `Segmentation` → جداکردن بخش‌های شبکه
- `Zones` → تقسیم شبکه بر اساس سطح امنیت
- `Defense in Depth` → چند لایه دفاع
- `VPN` → تونل امن
- `Firewall` → کنترل ترافیک
- `IDS` → Detect
- `IPS` → Detect + Block
- `Honeypot` → سیستم جعلی
- `Honeynet` → شبکه جعلی
- `Air Gap` → جداسازی کامل

### Authentication & Access
- `Identification` → ادعای هویت
- `Authentication` → اثبات هویت
- `Authorization` → تعیین مجوز
- `Accounting` → ثبت فعالیت
- `LDAP` → Directory
- `Kerberos` → Tickets
- `RADIUS` → Network Authentication
- `TACACS+` → Network/Admin Authentication
- `SAML` → Web SSO
- `MAC` → سیستم/Policy تصمیم می‌گیرد
- `DAC` → مالک تصمیم می‌گیرد
- `RBAC` → Role تصمیم می‌گیرد
- `ABAC` → Attributes + Conditions

### Wireless
- `WEP` → قدیمی و ناامن
- `Evil Twin` → AP جعلی با SSID مشابه
- `Rogue AP` → AP غیرمجاز
- `Jamming` → ایجاد نویز
- `Replay` → Capture + Resend
- `Bluejacking` → پیام ناخواسته Bluetooth
- `Bluesnarfing` → سرقت اطلاعات Bluetooth

### Cloud
- `SaaS` → Software
- `PaaS` → Platform
- `IaaS` → Infrastructure
- `Public` → عمومی
- `Private` → یک سازمان
- `Community` → چند سازمان با نیاز مشترک
- `Hybrid` → ترکیب
- `Type I` → Bare Metal
- `Type II` → Hosted
- `Host` → میزبان
- `Guest` → VM
- `VM Escape` → خروج از محیط VM
- `VM Sprawl` → VMهای زیاد و کنترل‌نشده
- `Multitenancy` → چند مشتری روی زیرساخت مشترک
- `CASB` → اعمال سیاست امنیتی Cloud

### Malware & Attacks
- `Virus` → آلودگی فایل/برنامه
- `Worm` → Self-Replicating
- `Trojan` → ظاهراً مفید، واقعاً مخرب
- `Ransomware` → رمزگذاری + باج
- `Rootkit` → مخفی‌کاری
- `Keylogger` → ثبت کلیدها
- `DoS` → یک/منبع حمله برای اختلال
- `DDoS` → چندین سیستم
- `MITM` → مهاجم وسط ارتباط
- `MITB` → دستکاری تراکنش مرورگر
- `SQLi` → Database
- `LDAP Injection` → Directory
- `XSS` → Script
- `CSRF/XSRF` → Request ناخواسته
- `ARP Poisoning` → IP ↔ MAC
- `DNS Poisoning` → Domain ↔ IP
- `Spoofing` → جعل
- `Replay` → دوباره ارسال
- `Session Hijacking` → سرقت Session
- `Clickjacking` → فریب برای Click
- `Typosquatting` → Domain مشابه

### Social Engineering
- `Phishing` → Email/Message
- `Vishing` → Voice
- `Smishing` → SMS
- `Whaling` → افراد مهم/مدیران
- `Tailgating` → پشت سر فرد مجاز
- `Shoulder Surfing` → نگاه‌کردن
- `Dumpster Diving` → زباله
- `Watering Hole` → سایت مورد علاقه قربانی
- `Mantrap` → دو در امنیتی

### Security Controls
- `Deterrent` → بازدارندگی
- `Preventive` → جلوگیری
- `Detective` → تشخیص
- `Corrective` → اصلاح
- `Compensating` → جایگزین
- `Technical` → فناوری
- `Administrative` → Policy
- `Awareness` → آموزش کاربر
- `Environmental` → محیط

### Cryptography
- `AES` → Symmetric
- `RSA` → Asymmetric
- `DH` → Key Exchange
- `SHA` → Hash
- `Hash` → Integrity
- `Digital Signature` → Integrity + Nonrepudiation
- `CA` → Certificate Authority
- `CRL` → Revoked List
- `OCSP` → بررسی آنلاین وضعیت Certificate

### Incident & Recovery
- `Preparation` → آماده‌سازی
- `Identification` → شناسایی
- `Containment` → محدودسازی
- `Eradication` → حذف تهدید
- `Recovery` → بازگردانی
- `Lessons Learned` → یادگیری
- `Incident Response` → پاسخ به حادثه
- `Disaster Recovery` → بازیابی پس از Disaster
- `Business Continuity` → ادامه کسب‌وکار

### Backup & Site
- `Full` → همه داده‌ها
- `Incremental` → از آخرین Backup
- `Differential` → از آخرین Full
- `Hot Site` → سریع‌ترین
- `Warm Site` → متوسط
- `Cold Site` → کندترین
- `Failover` → انتقال به سیستم جایگزین
- `Tabletop` → تمرین سناریویی

---

## نکته پایانی

این جزوه برای **مرور و جمع‌بندی** طراحی شده است. برای یادگیری عمیق‌تر، بهتر است هر اصطلاح را با یک سناریوی واقعی یا سؤال تستی تمرین کنی.

