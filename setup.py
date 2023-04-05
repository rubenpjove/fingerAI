from setuptools import setup, find_packages

setup(
    name='fingerai',
    version='1.1',
    author='rubenpjove',
    description='OS Fingerprinting Tool based on Artifial Intelligence',
    url='https://github.com/rubenpjove/fingerAI',
    packages=find_packages(),
    python_requires='>=3.11.2',
    install_requires=[
        'joblib==1.2.0',
        'pandas==1.4.4',
        'scapy==2.4.5',
        'scapy_p0f==1.0.5',
        'scikit-learn==1.1.2',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',
        'Topic :: Security',
        'Topic :: Fingerprinting',
        'Topic :: System :: Operating System',
    ],
)
