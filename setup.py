from setuptools import setup, find_packages

setup(
    name="msdefender-slack",
    version="0.1.0",
    description="Microsoft Defender Slack Notification System",
    author="Security Team",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.26.0",
        "requests>=2.28.2",
        "slack-sdk>=3.20.0",
    ],
) 