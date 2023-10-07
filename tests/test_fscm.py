#!/usr/bin/env python

from fscm import fscm


def pytest_content():
    assert fscm.system.pkg_is_installed('sudo')
    assert not fscm.system.pkg_is_installed('sudox')

    assert not fscm.system.pkg_install('sudo')  # does nothing

    assert fscm.this_dir_path().name == 'tests'
