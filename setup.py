from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read()
setup(
    name="AWSXenos",
    version="0.4.0",
    author="Costas Kourmpoglou",
    author_email="costas.kourmpoglou@airwalkconsulting.com",
    license="MIT",
    description="Scan and classify cross-account roles and resources in your AWS Account",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AirWalk-Digital/AWSXenos",
    py_modules=["awsxenos"],
    packages=find_packages(),
    install_requires=[requirements],
    python_requires=">=3.8",
    package_data={"": ["config.yaml", "accounts.json", "template.html"]},
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points="""
        [console_scripts]
        awsxenos=awsxenos.scan:cli
    """,
    keywords="aws iam cross-account roles security",
)
