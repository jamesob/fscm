import re
from pathlib import Path

import fscm
from fscm import ChangeList, run, s, p


pyversion_to_sha = {
    "3.11.0b4": "257e753db2294794fa8dec072c228f3f53fd541a303de9418854b3c2512ccbec",
    "3.11.0": "64424e96e2457abbac899b90f9530985b51eef2905951febd935f0e73414caeb",
}


def _extract_version(ver: str) -> tuple[int, int, int]:
    return tuple(int(i) for i in re.match(r"\d+\.\d+\.\d+", ver).group().split('.'))


def install_python3(version="3.11.0") -> ChangeList:
    if not (s.is_debian() or s.is_ubuntu()):
        raise NotImplementedError

    curr_version = None

    vertuple = _extract_version(version)

    if s.is_installed("python3"):
        curr_version = _extract_version(
            run("python3 --version", q=True, destructive=False).stdout.split("Python ")[-1]
        )
        if curr_version >= vertuple:
            return []

    ver_short = re.match(r"\d+\.\d+", version).group()
    ver_no_beta = re.match(r"\d+\.\d+\.\d+", version).group()
    tgz_fname = f"Python-{version}.tgz"

    s.pkgs_install(
        "curl build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev "
        "libssl-dev libreadline-dev libffi-dev libsqlite3-dev"
    )

    if not (dest := Path(f"/tmp/{tgz_fname}")).exists():
        url = f"https://www.python.org/ftp/python/{ver_no_beta}/{tgz_fname}"
        got = fscm.download_and_check_sha(url, pyversion_to_sha[version])

        if not dest.exists():
            fscm.run(f"mv {got} {dest}")

    untarred = dest.parent / dest.stem

    run(
        f"""
        cd {dest.parent} && \
        tar -xf {tgz_fname} && \
        cd {untarred} && \
        ./configure --prefix=/usr/local --enable-optimizations \
           --enable-loadable-sqlite-extensions --enable-shared \
           LDFLAGS="-Wl,-rpath /usr/local/lib" && \
        make -j $(nproc --ignore=1) >/dev/null
        """,
    ).assert_ok()

    run(f"cd {untarred} && make altinstall >/dev/null", sudo=True).assert_ok()

    binpath = Path("/usr/local/bin/python3")
    if binpath.exists():
        run(f"rm {binpath}", sudo=True)

    run(
        f"update-alternatives --install {binpath} python3 "
        f"/usr/local/bin/python{ver_short} 100",
        sudo=True,
    ).assert_ok()

    p(dest, sudo=True).rm("-rf")
    p(untarred, sudo=True).rm("-rf")

    if curr_version:
        return [fscm.cl(fscm.PkgUpgrade, "python3", str(curr_version), version)]
    return [fscm.cl(fscm.PkgAdd, "python3", version, "source")]
