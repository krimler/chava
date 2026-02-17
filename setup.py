from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="chava",
    version="1.0.0",
    author="Anonymous Authors",
    author_email="anonymous@example.com",
    description="A Verification-Aware Data Model for Trust-Carrying Data Processing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/chava",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "jsonpointer>=2.3,<3.0",
        "cryptography>=41.0.0,<42.0.0",
        "click>=8.1.0,<9.0.0",
        "rich>=13.5.0,<14.0.0",
        "PyYAML>=6.0,<7.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "chava=chava_cli:cli",
        ],
    },
)
