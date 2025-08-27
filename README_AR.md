# 🔍 ماسكانيير (Mous) - ماسح الأمان المتقدم

**ماسح ثغرات الويب الشامل**

<p align="center">
  <img src="mous/assets/logo/mous_logo.svg" alt="شعار Mous" width="200"/>
</p>

<p align="center">
  <a href="https://github.com/SaudiLinux"><img src="https://img.shields.io/badge/GitHub-SaudiLinux-blue.svg" alt="GitHub"></a>
  <a href="mailto:SayerLinux@gmail.com"><img src="https://img.shields.io/badge/Email-SayerLinux@gmail.com-red.svg" alt="Email"></a>
  <img src="https://img.shields.io/badge/Platform-Windows-blue.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.7+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>

## 🚀 نظرة عامة

ماسكانيير (Mous) هو ماسح ثغرات ويب قوي وشامل مصمم لتحديد مشكلات الأمان في تطبيقات الويب. يجمع بين الكشف التلقائي عن الثغرات مع تقنيات المسح الذكية لتوفير تقييمات أمان شاملة.

## ✨ المميزات

### 🔍 كشف الثغرات
- **حقن XSS** - كشف XSS الانعكاسي، المخزن، والمستند إلى DOM
- **حقن SQL** - كشف SQLi الاتحادي، الأعمى، المعتمد على الأخطاء، والزمني
- **تضمين الملفات المحلية (LFI)** - كشف اختراق المسارات وتضمين الملفات
- **تنفيذ الأوامر البعيد (RCE)** - اختبار حقن الأوامر وتنفيذ الشفرة
- **كشف المعلومات الحساسة** - كشف التعرض للبيانات الحساسة
- **سوء التكوينات** - رؤوس الأمان، قوائم الدليل، الملفات الافتراضية

### 🗄️ قاعدة البيانات والذكاء
- **قاعدة بيانات CVE** - قاعدة بيانات شاملة للثغرات مع تحديثات تلقائية
- **تكامل الاستغلال** - التكامل مع ExploitDB وMetasploit
- **كشف التواقيع** - تواقيع ثغرات معتمدة على الأنماط
- **التحديثات الفورية** - مزامنة تلقائية لقاعدة البيانات

### 📊 التقارير
- **تنسيقات متعددة** - تقارير HTML، CSV، XML، وJSON
- **الملخص التنفيذي** - نظرة عامة عالية المستوى للثغرات
- **النتائج التفصيلية** - تفاصيل كاملة للثغرات مع الأدلة
- **إرشادات الإصلاح** - تعليمات خطوة بخطوة للإصلاح

### ⚙️ التكوين
- **المسح المرن** - أنواع المسح وعمقه قابلين للتكوين
- **ضبط الأداء** - التحكم في المؤشرات وحد السرعة
- **دعم البروكسي** - تكوين HTTP/HTTPS/SOCKS proxy
- **المصادقة** - دعم طرق المصادقة المختلفة

## 🛠️ التثبيت

### المتطلبات المسبقة
- Python 3.7 أو أعلى
- نظام Windows

### التثبيت السريع
```bash
# انتقل إلى الدليل
cd mous

# تثبيت المتطلبات
pip install -r requirements.txt
```

### التثبيت باستخدام Docker
```bash
# بناء صورة Docker
docker build -t mous-scanner .

# التشغيل باستخدام Docker
docker run -it --rm mous-scanner python mous.py --help
```

## 🎯 الاستخدام

### الاستخدام الأساسي
```bash
# مسح عنوان URL واحد
python mous.py -u https://example.com

# مسح مع أنواع ثغرات محددة
python mous.py -u https://example.com --xss --sql

# مسح مع إخراج مخصص
python mous.py -u https://example.com -o reports/example_scan.html
```

### الاستخدام المتقدم
```bash
# مسح شامل مع جميع المميزات
python mous.py -u https://example.com \
  --all \
  --threads 20 \
  --timeout 60 \
  --output reports/comprehensive_scan.html \
  --format html

# المسح مع بروكسي
python mous.py -u https://example.com \
  --proxy http://proxy.example.com:8080 \
  --xss --sql

# المسح مع المصادقة
python mous.py -u https://example.com \
  --auth-type basic \
  --auth-user admin \
  --auth-pass password
```

### استخدام ملف التكوين
```bash
# استخدام تكوين مخصص
python mous.py -u https://example.com -c custom_config.json

# إنشاء تكوين عينة
python mous.py --generate-config
```

## 📋 خيارات سطر الأوامر

### تحديد الهدف
- `-u, --url` - عنوان URL المستهدف للمسح
- `-l, --list` - ملف يحتوي على قائمة عناوين URL للمسح
- `--ip` - عنوان IP المستهدف (للمسح الشبكي)

### خيارات المسح
- `--threads` - عدد المؤشرات المتزامنة (الافتراضي: 10)
- `--timeout` - مهلة الطلب بالثواني (الافتراضي: 30)
- `--user-agent` - سلسلة User-Agent المخصصة
- `--delay` - التأخير بين الطلبات بالثواني

### أنواع المسح
- `--xss` - تمكين مسح XSS
- `--sql` - تمكين مسح حقن SQL
- `--lfi` - تمكين مسح LFI
- `--rce` - تمكين مسح RCE
- `--info` - تمكين كشف المعلومات
- `--all` - تمكين جميع أنواع المسح

### خيارات الإخراج
- `-o, --output` - مسار ملف الإخراج
- `--format` - تنسيق التقرير (html, csv, xml, json)
- `--template` - قالب التقرير لاستخدامه

### التكوين
- `-c, --config` - مسار ملف التكوين
- `--generate-config` - إنشاء ملف تكوين عينة
- `--update-db` - تحديث قاعدة بيانات الثغرات

### خيارات قاعدة البيانات
- `--list-plugins` - قائمة المكونات الإضافية المتاحة
- `--update-plugins` - تحديث مكونات الثغرات الإضافية

### التفصيل
- `-v, --verbose` - تمكين الإخراج التفصيلي
- `-q, --quiet` - إخفاء الإخراج باستثناء الأخطاء

## 🔧 التكوين

### هيكل ملف التكوين
أنشئ `mous_config.json`:

```json
{
  "scanner": {
    "max_threads": 10,
    "request_timeout": 30,
    "user_agent": "Mous Security Scanner/1.0",
    "delay_between_requests": 1
  },
  "scan_types": {
    "xss": {
      "enabled": true,
      "payloads_file": "data/payloads/xss.txt"
    },
    "sql": {
      "enabled": true,
      "payloads_file": "data/payloads/sql.txt"
    }
  },
  "reporting": {
    "output_directory": "reports",
    "formats": ["html", "json"],
    "include_remediation": true
  },
  "proxy": {
    "enabled": false,
    "http_proxy": "http://proxy.example.com:8080"
  }
}
```

### متغيرات البيئة
```bash
set MOUS_THREADS=20
set MOUS_TIMEOUT=60
set MOUS_OUTPUT_DIR=C:\custom\reports
```

## 🎯 أمثلة سريعة

### مسح موقع اختبار
```bash
python mous.py -u http://testphp.vulnweb.com --all --format html --output test_report.html
```

### مسح متعدد الأهداف
```bash
# إنشاء ملف targets.txt
echo https://site1.com > targets.txt
echo https://site2.com >> targets.txt

# مسح جميع الأهداف
python mous.py -l targets.txt --xss --sql --format json
```

### مسح مع تقارير متعددة
```bash
python mous.py -u https://example.com \
  --all \
  --format html \
  --format json \
  --output comprehensive_scan
```

## 📞 الدعم

- **البريد الإلكتروني**: SayerLinux@gmail.com
- **GitHub**: https://github.com/SaudiLinux
- **الموقع**: https://github.com/SaudiLinux/Mous

## 📝 المساهمة

نرحب بالمساهمات! يرجى قراءة دليل المساهمة في `CONTRIBUTING.md`.

## 📄 الترخيص

هذا المشروع مرخص تحت MIT License - انظر ملف `LICENSE` للتفاصيل.

---

<div align="center">
  <strong>ماسكانيير (Mous) - حماية تطبيقاتك الويبية من الثغرات</strong>
</div>