#!/usr/bin/env python

from hypothesis import given
from hypothesis.strategies import text

from fscm import fscm


def test_content():
    assert fscm.system.pkg_is_installed('sudo')
    assert not fscm.system.pkg_is_installed('sudox')

    assert not fscm.system.pkg_install('sudo')  # does nothing

    assert fscm.this_dir_path().name == 'tests'


def test_pathhelper():
    path = fscm.p('/tmp/nonnnnn_existent')

    assert not path.exists()

    # Can access underlying Path methods.
    assert path.is_absolute()


@given(text())
def test_path_content(s):
    path = fscm.p("/tmp/fscm-test.txt")
    path.content(s)
    assert path.read_text() == s
