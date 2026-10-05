from setuptools import setup, find_packages

setup(
    name="api-security-tester",
    version="1.0.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "click>=8.1.0",
        "requests>=2.31.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "jinja2>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "apisec=apisec.cli:main",
        ],
    },
    author="Prateek Yadav",
    author_email="yprateek181@gmail.com",
    description="Automated security testing for REST APIs",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/prateek-ydv/api-security-tester",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
)
