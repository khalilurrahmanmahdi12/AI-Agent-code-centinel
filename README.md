# CodeSentinel AI — Multi-Agent Code Review & Automated Refactoring Platform

![IBM SkillsBuild](https://img.shields.io/badge/IBM_SkillsBuild-AI_Agent_for_Programming-0F62FE?logo=ibm&logoColor=white)
![Hacktiv8](https://img.shields.io/badge/Hacktiv8-Indonesia_Certified-EA580C?logo=academia&logoColor=white)
![Python 3.13](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-High_Performance-009688?logo=fastapi&logoColor=white)
![Pytest](https://img.shields.io/badge/Pytest-Automated_Testing-0A9EDC?logo=pytest&logoColor=white)
![OWASP Security](https://img.shields.io/badge/Security-OWASP_Top_10-E11D48?logo=owasp&logoColor=white)
![Antislop UI](https://img.shields.io/badge/UI_Design-Antislop_Modern-18181B?logo=tailwindcss&logoColor=white)

**CodeSentinel AI** adalah platform peninjau kode sumber (*code review*) dan perefaktor otomatis berbasis **Autonomous Multi-Agent AI System** yang dirancang dan dibangun oleh **KHALILURRAHMAN MAHDI** sesuai dengan standar kompetensi sertifikasi program pendidikan **IBM SkillsBuild University Education** bekerja sama dengan **Hacktiv8 Indonesia**: *"IT - AI Agent for Programming"*.

Aplikasi ini mengintegrasikan tim agen kecerdasan buatan mandiri yang memiliki spesialisasi peran (**QualitySentinel**, **SecuritySentinel**, **RefactorSentinel**, dan **TestSentinel**) di bawah koordinasi **Master Orchestrator**. Dilengkapi mesin ganda (*Dual-Engine*: LLM API dan *Built-in AST Heuristic Analyzer*), *live execution sandbox*, serta antarmuka web developer (*antislop UI*) yang modern, bersih, minimalis, dan sepenuhnya responsif di perangkat desktop maupun ponsel.

---

## 🚀 Live Demo & Kode Sumber

- 📜 **Sertifikat Kelulusan**: IBM SkillsBuild & Hacktiv8 (`Certificate ID: 02757/H8/CSR/ISUE/V/2026`)
- 💻 **Local Host**: `http://127.0.0.1:8000`
- 📁 **Repository**: `https://github.com/khalilurrahmanmahdi12/AI-Agent-code-centinel.git`
- 🌐 **Portfolio**: https://khalildev.web.id/

---

## ✨ Fitur Utama

### 💎 1. QualitySentinel Agent (Clean Code & AST Metrics)
Pemeriksa kualitas arsitektur kode dan kepatuhan standar PEP 8:
- Mengurai struktur kode menggunakan parser native **Abstract Syntax Tree (AST)**
- Menghitung metrik perangkat lunak: *Lines of Code* (LOC), jumlah fungsi & class, dan *Cyclomatic Complexity V(G)*
- Mendeteksi *code smells*: fungsi terlalu panjang, *bare except:*, *wildcard import* (`from module import *`), dan missing docstring
- Menghitung indeks keterpeliharaan (*Maintainability Index*) berbasis kompleksitas percabangan

### 🛡️ 2. SecuritySentinel Agent (OWASP Top 10 & CWE Detection)
Auditor keamanan aplikasi (*Application Security*) otomatis:
- **Deteksi Kredensial Bocor**: Menemukan *hardcoded secrets*, API key, auth token, dan AWS credentials secara instan
- **Pencegahan SQL Injection**: Mengidentifikasi query database berisiko akibat format string langsung (`f-string` / `%`)
- **Pencegahan Remote Code Execution (RCE)**: Mendeteksi penggunaan fungsi berbahaya seperti `eval()`, `exec()`, `os.system()`, dan `subprocess.run(shell=True)`
- Pemetaan ke standar industri dengan label keparahan presisi: `CRITICAL`, `HIGH`, `MEDIUM`, dan `LOW`

### ⚡ 3. RefactorSentinel Agent (Automated Diff & Production-Ready Refactor)
Perekayasa refaktorisasi kode otomatis:
- Memperbaiki seluruh celah keamanan dan *code smell* yang ditemukan agen auditor secara otomatis
- Mengganti kredensial statis dengan pemanggilan aman `os.getenv()`
- Mensanitasi query SQL menjadi *parameterized prepared queries*
- Mengonversi eksekusi shell rentan menjadi `subprocess.run(..., shell=False, check=True)`
- Menghasilkan patch standar industri **Unified Git Diff** (`+` penambahan hijau dan `-` penghapusan merah)

### 🧪 4. TestSentinel Agent & Live Sandbox Runner (Pytest Automation)
Pembuat *unit test suite* komprehensif dan penguji eksekusi nyata:
- Menganalisis *function signature* dan parameter untuk menyusun skenario uji otomatis
- Mencakup pengujian *Happy Path*, batas ekstrem (*Edge Cases / Boundary Values*), dan penanganan galat (*Exception Handling*)
- **Isolated Execution Sandbox**: Mengeksekusi suite `pytest` secara nyata di proses latar belakang terisolasi
- Menampilkan telemetri eksekusi langsung: status `PASS/FAIL`, durasi waktu (milidetik), dan log terminal *stdout/stderr*

### 🎯 5. Master Orchestrator & Scoring 4-Dimensi
Sistem orkestrasi pipeline agen terpadu:
- Mengelola aliran kerja sekuensial dan paralel antar agen
- Mengalkulasi indeks kesehatan kode komposit (0–100) berdasarkan 4 pilar:
  - 🛡️ **Security Posture** (Bobot 35%)
  - 💎 **Maintainability Index** (Bobot 25%)
  - ⚙️ **System Reliability** (Bobot 20%)
  - 🧪 **Testability Coverage** (Bobot 20%)
- Menghasilkan **Executive Summary** komprehensif yang dapat diunduh dalam format **JSON** dan **Markdown**

---

## 🏗️ Visualisasi Arsitektur Pipeline Multi-Agent

Alur kerja kolaboratif agen dari input kode hingga eksekusi pengujian:

```text
[1. User Source Code / Input File]
       ↓
[2. Master Orchestrator Agent]
       │
       ├─────────────────────────────────────────────┐
       ↓                                             ↓
  [3a. 💎 QualitySentinel]                      [3b. 🛡️ SecuritySentinel]
  (AST Analysis, Complexity, PEP 8)             (OWASP Top 10, CWE, Secrets)
       │                                             │
       └──────────────────────┬──────────────────────┘
                              ↓
                  [4. Finding Synthesizer]
                              ↓
                  [5. ⚡ RefactorSentinel]
               (Clean Code & Unified Git Diff)
                              ↓
                  [6. 🧪 TestSentinel]
               (Synthesize Pytest Test Cases)
                              ↓
             [7. 📦 Isolated Code Sandbox]
                 (Run Pytest in Subprocess)
                              ↓
     [8. Executive Report & Interactive Dashboard]
```

---

## 📱 Desain Responsif & Antislop UI

Aplikasi ini dirancang dengan estetika *high-craft developer tool* (terinspirasi dari Linear.app, GitHub Enterprise, dan Vercel):
- **Tampilan Antislop (Zinc Dark Theme)**: Menghindari warna gradien norak / *AI slop tropes*. Menggunakan palet *Dark Zinc* (`#09090b` / `#121215`) dengan garis batas tajam 1px solid (`#202025`).
- **Tipografi Resmi**: Menggunakan font **IBM Plex Sans** (selaras dengan IBM SkillsBuild) dan **JetBrains Mono** untuk angka, kode, dan telemetri data.
- **Tabel Audit Terstruktur & Diff Viewer**:
  - Kolom keparahan terstandarisasi (`CRITICAL`, `HIGH`, `MEDIUM`) dengan *Rule ID* dan nomor baris
  - Penampil patch Git Diff dengan penanda sintaksis bersih
- **Mobile-First Responsive Layout**:
  - *Grid layout* otomatis beralih menjadi kartu vertikal yang nyaman di smartphone tanpa pemotongan teks (*zero text cut-off*)
  - Pipeline 5-tahap agen diringkas menjadi *micro-pills stepper* yang presisi di layar ponsel
  - Tabel temuan otomatis bertransformasi menjadi *adaptive cards* dengan pembungkusan teks penuh (`word-break: break-word`)

---

## 🛠️ Teknologi yang Digunakan

- **Python 3.13**
- **FastAPI** (High-Performance Async Web Framework)
- **Uvicorn** (Lightning-Fast ASGI Server)
- **Pytest** (Automated Test Automation Framework)
- **Python Native AST Module** (`ast` & `dis`)
- **Pydantic v2** (Strict Data Validation & Schemas)
- **HTTPX** (Asynchronous HTTP Client)
- **Modern Semantic HTML5, CSS3 Variables, & Vanilla JavaScript (ES6+)**
- **Dukungan Dual-Engine**: Local Heuristic AST Engine & Cloud LLM API (Google Gemini 1.5 / OpenAI GPT-4o-mini)

---

## 🚀 Menjalankan Project

### 1. Clone atau Buka Folder Project
```bash
git clone https://github.com/khalilurrahmanmahdi12/AI-Agent-code-centinel.git
cd AI-Agent-code-centinel
```

### 2. Install Dependensi
```bash
pip install -r requirements.txt
```

### 3. Jalankan Pengujian Unit & Integrasi
Pastikan seluruh agen dan sandbox berjalan sempurna:
```bash
python -m pytest tests/ -v
```

### 4. Jalankan Aplikasi Web
```bash
python main.py
```

### 5. Buka di Browser
Kunjungi alamat berikut di browser desktop atau mobile Anda:
```text
http://127.0.0.1:8000
```

---

## 📂 Struktur Utama Project

```text
code-sentinel-agent/
├── agents/                      # Modul Implementasi Agen AI Mandiri
│   ├── base_agent.py            # Kelas Abstrak Agen & Logger
│   ├── orchestrator.py          # Master Orchestrator & Scoring Engine
│   ├── quality_agent.py         # QualitySentinel (Clean Code & Ast Metrics)
│   ├── security_agent.py        # SecuritySentinel (OWASP & Vulnerability Auditor)
│   ├── refactor_agent.py        # RefactorSentinel (Patch & Unified Diff Generator)
│   └── test_generator_agent.py  # TestSentinel (Pytest Suite Synthesis)
├── core/                        # Mesin Analisis & Eksekusi Inti
│   ├── ast_analyzer.py          # Native Python AST Parser & Heuristic Rules
│   ├── llm_client.py            # Multi-Provider Client (Gemini, OpenAI, Offline)
│   ├── models.py                # Skema Data Pydantic (Request, Response, Metrics)
│   └── sandbox.py               # Runner Pengujian Pytest dalam Subproses Terisolasi
├── samples/                     # Sampel Kode Uji Dunia Nyata
│   ├── vulnerable_auth.py       # Sampel Otentikasi Rentan SQLi & Hardcoded Secrets
│   └── messy_analytics.py      # Sampel Kompleksitas Tinggi & Bottleneck Memori
├── static/                      # Antarmuka Pengguna (Web UI Dashboard)
│   ├── index.html               # Markup Semantik & Struktur Dashboard
│   ├── styles.css               # Desain Antislop Zinc Dark & Media Queries Mobile
│   └── app.js                   # State Management, API Calls, & Diff Formatter
├── tests/                       # Pengujian Otomatis Proyek
│   └── test_agents.py           # Unit & Integration Tests untuk Pipeline Agen
├── main.py                      # REST API Endpoints & Server FastAPI
├── requirements.txt             # Daftar Dependensi Python
└── README.md                    # Dokumentasi Teknis dan Panduan Lengkap
```

---

## 📌 Status Project & Kepatuhan Rubrik Sertifikat

- ✅ **Completeness & Feasibility (40%)**: Pipeline *end-to-end* yang berfungsi penuh, feasible diimplementasikan, dan telah lolos 100% pengujian unit `pytest`.
- ✅ **Creativity & Innovation (25%)**: Kolaborasi multi-agent dengan persona terspesialisasi, *dual-engine* offline & cloud, serta *live execution sandbox*.
- ✅ **System Design & Architecture (15%)**: Desain arsitektur modular, terpisah antara layer agen, core analyzer, dan presentation UI.
- ✅ **Background & Impact (20%)**: Menjawab permasalahan nyata developer (mengurangi bottleneck *code review* dan mencegah kebocoran keamanan ke production).
- ✅ **Desain Antislop & 100% Mobile Responsive**: Tampilan developer-grade yang rapi dan bebas dari kesan *AI slop*.

---

## 👨💻 Developer & Creator

**KHALILURRAHMAN MAHDI**  
*Software Engineer - Full Stack Developer*  
IBM SkillsBuild & Hacktiv8 Certified: *IT - AI Agent for Programming*

- 📜 **Sertifikat Kelulusan**: [IBM SkillsBuild & Hacktiv8 (ID: 02757/H8/CSR/ISUE/V/2026)]
- 🔗 **GitHub**: [github.com/khalilurrahmanmahdi12](https://github.com/khalilurrahmanmahdi12)
- 💼 **Portofolio**: https://khalildev.web.id/

---

## ⭐ Dukungan

Jika project ini bermanfaat dan menarik bagi Anda, jangan lupa berikan ⭐ pada repositori ini!
