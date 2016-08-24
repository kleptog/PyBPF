import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "pybpf",
    version = "0.1",
    author = "Martijn van Oosterhout",
    author_email = "kleptog@gmail.com",
    description = ("A BPF assembler, dissembler, executer and debugger in Python"),
    license = "BSD",
    keywords = "bpf assembler disassembler",
    url = "http://packages.python.org/pybpf",
    packages=['pybpf', 'tests'],
    long_description=read('README.md'),
    install_requires=['ply'],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Operating System :: POSIX",
        "Topic :: Software Development :: Assemblers",
        "Topic :: Software Development :: Disassemblers",
        "License :: OSI Approved :: BSD License",
    ],
    entry_points={
        'console_scripts': [
            'bpf = pybpf.main:main',
        ]
    },
)
