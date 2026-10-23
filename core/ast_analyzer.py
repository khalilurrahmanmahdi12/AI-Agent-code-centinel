import ast
import re
from typing import List, Dict, Any, Tuple
from core.models import AgentFinding, FindingCategory, Severity, CodeMetrics


class ASTAnalyzer:
    """Analyzes Python code using Python's native AST parser and pattern heuristics."""

    def __init__(self, code: str):
        self.code = code
        self.lines = code.splitlines()
        self.tree = None
        self.syntax_error = None
        try:
            self.tree = ast.parse(code)
        except SyntaxError as e:
            self.syntax_error = f"Syntax Error at line {e.lineno}: {e.msg}"

    def get_metrics(self) -> CodeMetrics:
        loc = len([line for line in self.lines if line.strip() and not line.strip().startswith("#")])
        if not self.tree:
            return CodeMetrics(loc=loc, num_functions=0, num_classes=0, cyclomatic_complexity=1, maintainability_index=50.0)

        num_functions = sum(1 for node in ast.walk(self.tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
        num_classes = sum(1 for node in ast.walk(self.tree) if isinstance(node, ast.ClassDef))

        # Cyclomatic complexity approximation: 1 + decision points (if, for, while, and, or, except, with)
        complexity = 1
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.If, ast.For, ast.While, ast.AsyncFor, ast.ExceptHandler, ast.With, ast.AsyncWith)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1

        # Maintainability index simplified approximation (0 to 100)
        # Higher loc & complexity reduces index
        mi = max(10.0, min(100.0, 100.0 - (complexity * 2.5) - (loc * 0.15)))

        return CodeMetrics(
            loc=loc,
            num_functions=num_functions,
            num_classes=num_classes,
            cyclomatic_complexity=complexity,
            maintainability_index=round(mi, 1)
        )

    def find_security_issues(self) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        # 1. Check for hardcoded secrets / credentials / tokens
        secret_patterns = [
            (r'(?i)(api[_-]?key|secret|password|token|auth_token)\s*=\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', "Kredensial / Kunci API Tertulis Langsung (Hardcoded Secret)"),
            (r'(?i)AWS_[A-Z_]*KEY\s*=\s*["\'][^"\']+["\']', "Kredensial AWS Tertulis Langsung"),
        ]
        for line_no, line in enumerate(self.lines, start=1):
            for pattern, title in secret_patterns:
                match = re.search(pattern, line)
                if match:
                    findings.append(AgentFinding(
                        category=FindingCategory.SECURITY,
                        severity=Severity.HIGH,
                        title=title,
                        description=f"Ditemukan token atau kunci rahasia sensitif yang ditulis langsung di dalam kode pada baris {line_no}. Ini berisiko tinggi bocor ke publik atau repositori bersama.",
                        line_number=line_no,
                        suggestion="Pindahkan nilai rahasia ke environment variable menggunakan `os.getenv('NAMA_KEY')` atau simpan di file `.env` yang tidak di-commit ke Git.",
                        rule_id="SEC-001"
                    ))

        # 2. Check for SQL Injection (string concatenation/formatting in query executions)
        sql_patterns = [
            (r'(?i)(execute|cursor\.execute)\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\%.*["\']', "Potensi Celah SQL Injection (Format String %)"),
            (r'(?i)(execute|cursor\.execute)\s*\(\s*f["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\{.*\}', "Potensi Celah SQL Injection (f-string)"),
            (r'(?i)(execute|cursor\.execute)\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*\w+', "Potensi Celah SQL Injection (Penggabungan String +)")
        ]
        for line_no, line in enumerate(self.lines, start=1):
            for pattern, title in sql_patterns:
                if re.search(pattern, line):
                    findings.append(AgentFinding(
                        category=FindingCategory.SECURITY,
                        severity=Severity.CRITICAL,
                        title=title,
                        description=f"Pembuatan query database SQL secara langsung menggabungkan input pengguna pada baris {line_no}. Penyerang dapat menyusupkan perintah berbahaya untuk membaca, mengubah, atau menghapus seluruh isi database.",
                        line_number=line_no,
                        suggestion="Gunakan parameterized queries (prepared statements), contohnya: `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`.",
                        rule_id="SEC-002"
                    ))

        # 3. AST Inspection for dangerous calls: eval, exec, os.system, subprocess with shell=True
        if self.tree:
            for node in ast.walk(self.tree):
                if isinstance(node, ast.Call):
                    # eval() or exec()
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ('eval', 'exec'):
                            findings.append(AgentFinding(
                                category=FindingCategory.SECURITY,
                                severity=Severity.CRITICAL,
                                title=f"Penggunaan Fungsi Berbahaya `{node.func.id}()`",
                                description=f"Eksekusi kode secara dinamis menggunakan `{node.func.id}()` pada baris {node.lineno} sangat berbahaya dan dapat memicu celah eksekusi kode jarak jauh (Remote Code Execution / RCE).",
                                line_number=node.lineno,
                                suggestion=f"Hindari penggunaan `{node.func.id}()`. Gunakan `ast.literal_eval()` untuk memproses nilai literal atau `json.loads()` untuk membaca data JSON.",
                                rule_id="SEC-003"
                            ))
                    # os.system()
                    elif isinstance(node.func, ast.Attribute):
                        if node.func.attr == 'system' and getattr(node.func.value, 'id', '') == 'os':
                            findings.append(AgentFinding(
                                category=FindingCategory.SECURITY,
                                severity=Severity.HIGH,
                                title="Eksekusi Perintah Shell Berisiko (`os.system`)",
                                description=f"Menjalankan perintah sistem operasi via `os.system` pada baris {node.lineno} tanpa sanitasi ketat dapat memicu Command Injection oleh pihak tidak berwenang.",
                                line_number=node.lineno,
                                suggestion="Gunakan modul `subprocess.run([...], shell=False)` dengan memasukkan perintah dan argumennya dalam bentuk list string.",
                                rule_id="SEC-004"
                            ))
                        # subprocess.run/call/Popen with shell=True
                        elif node.func.attr in ('run', 'Popen', 'call') and getattr(node.func.value, 'id', '') == 'subprocess':
                            for kw in node.keywords:
                                if kw.arg == 'shell' and getattr(kw.value, 'value', False) is True:
                                    findings.append(AgentFinding(
                                        category=FindingCategory.SECURITY,
                                        severity=Severity.HIGH,
                                        title="Eksekusi Subproses dengan `shell=True`",
                                        description=f"Menjalankan subproses dengan opsi `shell=True` pada baris {node.lineno} membuka celah injeksi perintah shell.",
                                        line_number=node.lineno,
                                        suggestion="Ubah argumen menjadi `shell=False` dan kirimkan perintah beserta argumennya dalam format list string.",
                                        rule_id="SEC-005"
                                    ))

        return findings

    def find_quality_issues(self) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        if self.syntax_error:
            findings.append(AgentFinding(
                category=FindingCategory.CODE_QUALITY,
                severity=Severity.CRITICAL,
                title="Kesalahan Sintaksis (Syntax Error)",
                description=f"Terjadi kesalahan sintaksis: {self.syntax_error}",
                line_number=1,
                suggestion="Perbaiki kesalahan penulisan kode agar program dapat di-compile dan dijalankan dengan benar.",
                rule_id="QUAL-000"
            ))
            return findings

        if not self.tree:
            return findings

        # 1. Bare except clauses (except:)
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    findings.append(AgentFinding(
                        category=FindingCategory.CODE_QUALITY,
                        severity=Severity.MEDIUM,
                        title="Klausul `except:` Polos Tanpa Tipe Exception",
                        description=f"Blok `except:` tanpa tipe error pada baris {node.lineno} akan menangkap semua kesalahan termasuk sinyal keluar sistem (SystemExit dan KeyboardInterrupt), sehingga menyulitkan proses debugging saat aplikasi bermasalah.",
                        line_number=node.lineno,
                        suggestion="Tentukan jenis error secara spesifik, contoh: `except (ValueError, KeyError) as e:` atau minimal `except Exception as e:`.",
                        rule_id="QUAL-001"
                    ))

        # 2. Function length and excessive complexity
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body_length = len(node.body)
                if body_length > 25:
                    findings.append(AgentFinding(
                        category=FindingCategory.MAINTAINABILITY,
                        severity=Severity.LOW,
                        title=f"Fungsi `{node.name}` Terlalu Panjang ({body_length} baris kode)",
                        description=f"Fungsi `{node.name}` pada baris {node.lineno} memiliki {body_length} baris pernyataan, melebihi batas ideal keterbacaan (maksimal 25 baris).",
                        line_number=node.lineno,
                        suggestion="Pecah fungsi ini menjadi fungsi-fungsi pembantu (helper functions) yang lebih kecil sesuai prinsip Single Responsibility.",
                        rule_id="QUAL-002"
                    ))

                # Missing docstring
                if not ast.get_docstring(node):
                    findings.append(AgentFinding(
                        category=FindingCategory.MAINTAINABILITY,
                        severity=Severity.INFO,
                        title=f"Dokumentasi Docstring Belum Ada pada `{node.name}`",
                        description=f"Fungsi `{node.name}` pada baris {node.lineno} belum memiliki docstring penjelas mengenai fungsi, parameter yang diterima, atau nilai yang dikembalikan.",
                        line_number=node.lineno,
                        suggestion="Tambahkan komentar docstring standar PEP 257 di awal fungsi untuk menjelaskan tujuan fungsi, argumen, dan return value.",
                        rule_id="QUAL-003"
                    ))

        # 3. Unused imports or wildcard imports
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == '*':
                        findings.append(AgentFinding(
                            category=FindingCategory.CODE_QUALITY,
                            severity=Severity.MEDIUM,
                            title="Impor Wildcard (`from module import *`)",
                            description=f"Impor wildcard pada baris {node.lineno} mencemari namespace global dan menyamarkan asal-usul fungsi atau variabel yang digunakan.",
                            line_number=node.lineno,
                            suggestion="Impor hanya fungsi atau kelas yang benar-benar digunakan, contoh: `from math import sqrt, pi`.",
                            rule_id="QUAL-004"
                        ))

        # 4. Inefficient string concatenation in loops
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.For, ast.While)):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.AugAssign) and isinstance(sub.op, ast.Add):
                        findings.append(AgentFinding(
                            category=FindingCategory.PERFORMANCE,
                            severity=Severity.LOW,
                            title="Penggabungan Teks Berulang di Dalam Loop (`+=`)",
                            description=f"Penggabungan string berulang kali di dalam loop pada baris {sub.lineno} menyebabkan alokasi memori yang boros (O(n²)).",
                            line_number=sub.lineno,
                            suggestion="Kumpulkan teks ke dalam list lalu gabungkan sekaligus di akhir menggunakan `''.join(daftar_teks)` agar performa tetap cepat.",
                            rule_id="PERF-001"
                        ))
                        break

        return findings
