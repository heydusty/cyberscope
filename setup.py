"""
CyberScope — AI Log Anomaly Detector
Built by DUSTY (Akshat Singh Mehrotra)
© 2026 Dusty | dusty@dustyhive.com
"""

from setuptools import setup, find_packages

setup(
    name="cyberscope",
    version="1.0.0",
    author="Dusty (Akshat Singh Mehrotra)",
    author_email="dusty@dustyhive.com",
    description="AI-powered log anomaly detector using Isolation Forest — Built by DUSTY",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/YOUR_USERNAME/cyberscope",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.21.0",
        "scikit-learn>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "cyberscope=detect:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    license="MIT",
)
