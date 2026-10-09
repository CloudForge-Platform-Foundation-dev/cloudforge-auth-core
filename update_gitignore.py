"""
Update .gitignore to exclude helper scripts and build artifacts.
"""
from pathlib import Path

gitignore = Path(".gitignore")

# อ่านเนื้อหาเดิม (ถ้ามี)
if gitignore.exists():
    content = gitignore.read_text(encoding="utf-8")
else:
    content = ""

# เพิ่ม patterns ที่ต้องการ
patterns_to_add = [
    "# Helper scripts (temporary)",
    "add_tests.py",
    "create_integration_tests.py",
    "create_unit_tests.py",
    "fix_config.py",
    "fix_test_jwks.py",
    "fix_test_jwks_imports.py",
    "setup_tests.py",
    "",
    "# Build artifacts",
    "src/cloudforge_auth_core.egg-info/",
    "src/cloudforge_auth_core/__pycache__/",
    "tests/__pycache__/",
    "*.egg-info/",
    "__pycache__/",
    "",
    "# Testing",
    ".pytest_cache/",
    "",
]

# เช็คว่ามี patterns เหล่านี้อยู่แล้วไหม
new_patterns = []
for pattern in patterns_to_add:
    if pattern and pattern not in content:
        new_patterns.append(pattern)

if new_patterns:
    content += "\n" + "\n".join(new_patterns) + "\n"
    gitignore.write_text(content, encoding="utf-8")
    print("✅ Updated .gitignore")
else:
    print("ℹ️  .gitignore already up to date")