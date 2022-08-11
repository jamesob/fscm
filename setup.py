from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()


setup(
    author="James O'Beirne",
    author_email='james.obeirne@pm.me',
    python_requires='>=3.9',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
    ],
    description="fucking simple configuration management",
    license="MIT license",
    include_package_data=True,
    long_description=readme,
    long_description_content_type='text/markdown',
    keywords='fscm',
    name='fscm',
    packages=find_packages(),
    url='https://github.com/jamesob/fscm',
    extras_require={
        'mitogen': [
            # Fork of mitogen required to support pickling whitelist.
            # See https://github.com/mitogen-hq/mitogen/pull/953
            'mitogen @ git+ssh://git@github.com/jamesob/mitogen.git'
        ],
    },
    version='0.0.4',
)
