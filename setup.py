import setuptools

setuptools.setup(
    name="nidb",
    version="0.0.1",
    install_requires=["distorm3", "pyptrace"],
    packages=setuptools.find_packages(),
)

