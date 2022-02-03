#!/usr/bin/env python3
import fscm

fscm.file_('/tmp/fscm.test', fscm.template('./test.template'))
fscm.lineinfile('/tmp/fscm.test', 'foo = REPLACED', 'foo = .*')
