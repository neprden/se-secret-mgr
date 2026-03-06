from pathlib import Path

from setuptools import setup


README = Path(__file__).with_name("README.md").read_text(encoding="utf-8")


setup(
    name="se-secret-mgr",
    version="0.1.0",
    description="Small CLI secret manager based on age + AES-256-GCM",
    long_description=README,
    long_description_content_type="text/markdown",
    python_requires=">=3.10",
    install_requires=[
        "click>=8.1",
        "cryptography>=41",
    ],
    extras_require={
        "clipboard": ["pyperclip>=1.8"],
        "test": [
            "pytest>=8",
            "pytest-cov>=5",
        ],
    },
    scripts=["se-mgr.py"],
)
