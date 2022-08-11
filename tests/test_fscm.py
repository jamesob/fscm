#!/usr/bin/env python

from fscm import fscm


def test_content(response):
    """Sample pytest test function with the pytest fixture as an argument."""
    # from bs4 import BeautifulSoup
    # assert 'GitHub' in BeautifulSoup(response.content).title.string

    assert fscm.system.pkg_is_installed('sudo')
    assert not fscm.system.pkg_is_installed('sudox')

    assert not fscm.system.pkg_install('sudo')  # does nothing

    assert fscm.this_dir_path().name == 'tests'
