"""Setup script for SkillGuard."""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="skillguard-cli",
    version="1.0.0",
    author="SkillGuard Team",
    author_email="",
    description="🛡️ Lightweight AI Agent Skill Security Scanner - Zero Dependencies",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gitstq/SkillGuard-CLI",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "skillguard=skillguard.cli:main",
        ],
    },
    keywords="ai agent skill security scanner claude cursor copilot mcp",
    project_urls={
        "Bug Reports": "https://github.com/gitstq/SkillGuard-CLI/issues",
        "Source": "https://github.com/gitstq/SkillGuard-CLI",
    },
)
