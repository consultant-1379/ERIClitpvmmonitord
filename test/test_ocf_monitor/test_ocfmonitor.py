from nose import tools
import ocf_monitor
import os
import logging
import unittest
import tempfile
import stat
import shutil

HOSTS_EXAMPLE = """
# comment blah-monitor
# 123.123.1.1  host-monitor
127.0.0.1 localhost localhost.localdomain
10.10.10.10 other-monitor
10.10.10.20 test
10.10.10.30 monitor
123.123.1.5  host-monitor
"""

FILE_EXAMPLE = """
#!/bin/bash

exit 0
"""

class TestOcfMonitor(unittest.TestCase):
    def test_ocf_config_default(self):
        oc = ocf_monitor.OcfConfig()
        tools.eq_(12987, oc.port)
        tools.eq_(30, oc.log_level) # 30 == WARNING
        tools.eq_(ocf_monitor.OcfConfig.SCRIPT_PATH, oc.script_path)

    def test_ocf_config_error(self):
        os.environ['OCF_TIMEOUT'] = 'x'
        os.environ['OCF_LOG_LEVEL'] = 'doesntexist'
        oc = ocf_monitor.OcfConfig()
        tools.eq_(30, oc.log_level) # 30 == WARNING
        tools.eq_(60.0, oc.timeout)

    def test_ocf_config_env(self):
        os.environ['OCF_PORT'] = '8000'
        os.environ['OCF_SCRIPT_PATH'] = '/tmp'
        os.environ['OCF_LOG_LEVEL'] = 'warn'

        oc = ocf_monitor.OcfConfig()
        tools.eq_(8000, oc.port)
        tools.eq_(logging.WARN, oc.log_level)
        tools.eq_('/tmp', oc.script_path)

    def test_ocf_find_files_order(self):
        td = tempfile.mkdtemp()
        fn1 = os.path.join(td, 's2')
        tf1 = open(fn1 , 'w')
        tf1.write(FILE_EXAMPLE)
        os.fchmod(tf1.fileno(), stat.S_IXUSR | stat.S_IXGRP)
        tf1.close()
        fn2 = os.path.join(td, 's1')
        tf2 = open(fn2, 'w')
        tf2.write(FILE_EXAMPLE)
        os.fchmod(tf2.fileno(), stat.S_IXUSR | stat.S_IXGRP)
        tf2.close()
        fnh = os.path.join(td, '.h1')
        th = open(fnh, 'w')
        th.write(FILE_EXAMPLE)
        os.fchmod(th.fileno(), stat.S_IXUSR | stat.S_IXGRP)
        th.close()
        sr = ocf_monitor.ScriptRunner()
        r1 = sr.find_scripts(td)
        self.assertTrue('s2' in r1[1])
        self.assertTrue('s1' in r1[0])
        self.assertTrue('h1' not in ''.join(r1))
        shutil.rmtree(td)

    def test_ocf_find_files_order(self):
        td = tempfile.mkdtemp()
        fn1 = os.path.join(td, 's2')
        tf1 = open(fn1 , 'w')
        tf1.write(FILE_EXAMPLE)
        tf1.close()
        sr = ocf_monitor.ScriptRunner()
        r1 = sr.find_scripts(td)
        self.assertTrue(sr.has_nonexec)
        shutil.rmtree(td)
