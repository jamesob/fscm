from setuptools import setup

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
    py_modules=['fscm'],
    url='https://github.com/jamesob/fscm',
    version='0.0.2',
)
