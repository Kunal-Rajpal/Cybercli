from setuptools import setup, find_packages
setup(
    name="cybercli", version="1.0.0",
    description="AI-Powered VAPT Platform",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=["aiohttp>=3.9.0","typer[all]>=0.9.0","rich>=13.0.0"],
    entry_points={"console_scripts":["cybercli=cybercli.main:main"]},
)
