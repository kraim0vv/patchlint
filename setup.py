from setuptools import setup, find_packages

setup(
    name="patchlint",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "patchlint": ["templates/*.html"],
    },
    install_requires=[
        "httpx>=0.25.0",
        "rich>=13.5.0",
        "click>=8.1.0",
        "jinja2>=3.1.2",
    ],
    entry_points={
        "console_scripts": [
            "patchlint=patchlint.cli:main",
        ],
    },
)
