"""
setup.py - Package configuration for A-HIDS.

A-HIDS (AI-based Host Intrusion Detection System) setup script.
"""

from setuptools import setup, find_packages


def read_requirements():
    """Read requirements from requirements.txt."""
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [
            line.strip()
            for line in fh
            if line.strip() and not line.startswith("#")
        ]


with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()


setup(
    name="a-hids",
    version="1.0.0",
    author="A-HIDS Team",
    author_email="ahids@example.com",
    description=(
        "AI-based Host Intrusion Detection System - "
        "نظام كشف التسلل المستند إلى الذكاء الاصطناعي"
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/a-hids",
    packages=find_packages(exclude=["tests*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "ahids-server=server.main:main",
            "ahids-client=client.main:main",
            "ahids-dashboard=dashboard.app:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["config/*.yaml", "dashboard/templates/*.html",
             "dashboard/static/**/*"],
    },
)
