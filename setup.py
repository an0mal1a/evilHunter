from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="evilHunter",
    version="0.2.18",
    description="Cracking WiFi(KCRACK)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="an0mal1a",
    url="https://github.com/an0mal1a/evilHunter",
    author_email="pablodiez024@proton.me",
    packages=["words", "C"],
    scripts=["evilHunter.py", "evilCracker.py", "C/evilCracker.c"],
    install_requires=[
        'colorama',
        'tqdm',
],

)
