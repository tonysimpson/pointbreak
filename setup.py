import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

ptraceunwind_extension = setuptools.Extension(
    'pointbreak.ptraceunwind',	
    sources=['pointbreak/ptraceunwind.c'],
    libraries=['unwind-generic', 'unwind-ptrace'],
    #extra_compile_args=['-g', '-fno-omit-frame-pointer', '-O0'], # used for performance/debug
)


setuptools.setup(
    name="pointbreak",
    version="0.0.2",
    author="Tony Simpson",
    author_email="agjasimpson@gmail.com",
    description="System process debug and analysis library.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tonysimpson/pointbreak",
    install_requires=["distorm3", "pyptrace", "pyelftools"],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    ext_modules=[ptraceunwind_extension],
    packages=setuptools.find_packages(),
    classifiers=(
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    )
)

