import setuptools

setuptools.setup(
    name="pointbreak",
    version="0.0.1",
    install_requires=["distorm3", "pyptrace", "pyelftools"],
    packages=setuptools.find_packages(),
    setup_requires=['pytest-runner'],
    tests_require=['pytest']
)

