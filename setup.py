import os
import re
from setuptools import setup, find_packages

regexp = re.compile(r'.*__version__ = [\'\"](.*?)[\'\"]', re.S)

base_package = 'rastrea2r'
base_path = os.path.dirname(__file__)

init_file = os.path.join(base_path, 'src', 'rastrea2r', '__init__.py')
with open(init_file, 'r') as f:
    module_content = f.read()

    match = regexp.match(module_content)
    if match:
        version = match.group(1)
    else:
        raise RuntimeError(
            'Cannot find __version__ in {}'.format(init_file))

with open('README.rst', 'r') as f:
    readme = f.read()

with open('CHANGELOG.rst', 'r') as f:
    changes = f.read()

with open('requirements.txt', 'r') as f:
    requirements = [line for line in f.read().split('\n') if len(line.strip())]


if __name__ == '__main__':
    setup(
        name='rastrea2r',
        description='rastrea2r',
        long_description='\n\n'.join([readme, changes]),
        license='MIT license',
        url='https://github.com/rastrea2r/rastrea2r',
        version=version,
        author='Ismael Valenzuela @aboutsecurity',
        author_email='ismael.valenzuela@gmail.com',
        maintainer='Sudheendra Bhat',
        maintainer_email='bhat.sudheendra@gmail.com',
        install_requires=requirements,
        keywords=['rastrea2r'],
        package_dir={'': 'src'},
        packages=find_packages('src'),
        zip_safe=False,
        classifiers=['Development Status :: 3 - Alpha',
                     'Intended Audience :: Developers',
                     'Programming Language :: Python :: 2.7']
    )
