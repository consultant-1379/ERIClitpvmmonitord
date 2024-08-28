#!/usr/bin/python
import logging
import logging.handlers
import errno
import multiprocessing
import os
import os.path
import select
import signal
import socket
import subprocess
import sys
import threading
import time

from collections import namedtuple

try:
    # Python 2
    import SimpleHTTPServer
    import SocketServer
except ImportError:
    # Python 3
    import http.server as SimpleHTTPServer
    import socketserver as SocketServer

PID_FILE = '/var/run/vmmonitor.pid'
httpd_server = None
conn_proc = None
conn_queue = None  # created later
exec_agents = None  # populated later

def _eintr_retry(func, *args):
    """restart a system call interrupted by EINTR"""
    while True:
        try:
            return func(*args)
        except (OSError, select.error) as e:
            if e.args[0] != errno.EINTR:
                raise


def daemonize():
    try:
        pid = os.fork()
        if pid > 0:
            # pid zero = child
            sys.exit(0)
    except OSError as e:
        log.critical("daemonize failed: [Errno %d] %s", e.errno, e.strerror)
        sys.exit(1)

    # decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        log.critical("daemonize failed: [Errno %d] %s", e.errno, e.strerror)
        sys.exit(1)

    # Redirect standard file descriptors
    dev_null = open('/dev/null', 'r+')
    os.dup2(dev_null.fileno(), sys.stdin.fileno())
    os.dup2(dev_null.fileno(), sys.stdout.fileno())
    os.dup2(dev_null.fileno(), sys.stderr.fileno())

    return


def end_program(signum, frame):
    if exec_agents:
        sys.exit(0)

    log.debug('Server shutdown')
    conn_queue.close_all()
    httpd_server.shutdown()
    conn_proc[0].shutdown()
    conn_proc[1].shutdown()
    log.debug('Threads shutdown')
    httpd_server.server_close()
    try:
        os.remove(PID_FILE)
    except (OSError, IOError) as e:
        log.error("Error removing pid file: %s", e.strerror)
    sys.exit(0)

signal.signal(signal.SIGTERM, end_program)  # so we can handle kill gracefully
signal.signal(signal.SIGINT, end_program)  # so we can handle ctrl-c


class OcfConfig(object):
    PORT = 12987
    SCRIPT_PATH = '/usr/lib/ocf/resource.d'
    LOG_PATH = '/var/log/vmmonitor.log'
    LOG_LEVEL = "WARNING"
    LOG_LEVEL_OFF_VALUE = 100
    TIMEOUT = 60.0
    REQUEST_TIMEOUT = TIMEOUT

    def __init__(self):
        log_level_dict = dict([(k, getattr(logging, k))\
                                for k in dir(logging) if\
                                k.isupper() and not '_' in k])
        log_level_dict['OFF'] = self.LOG_LEVEL_OFF_VALUE
        self.port = int(os.environ.get('OCF_PORT', OcfConfig.PORT))
        self.script_path = os.environ.get('OCF_SCRIPT_PATH',
                                            OcfConfig.SCRIPT_PATH)
        log_level = os.environ.get('OCF_LOG_LEVEL',
                                     OcfConfig.LOG_LEVEL).upper()
        timeout_str = os.environ.get('OCF_TIMEOUT', OcfConfig.TIMEOUT)
        try:
            self.timeout = float(timeout_str)
            OcfConfig.REQUEST_TIMEOUT = self.timeout
        except ValueError:
            sys.stderr.write("Invalid OCF_TIMEOUT:"
                             "%s (must be a number)\n" % (timeout_str,))
            sys.stderr.write("Using default: %d\n" %
                                (OcfConfig.TIMEOUT))
            self.timeout = OcfConfig.TIMEOUT

        try:
            self.log_level = log_level_dict[log_level]
        except KeyError:
            sys.stderr.write("Invalid OCF_LOG_LEVEL: %s\n" % (log_level,))
            sys.stderr.write("Using default: %s\n" %
                                (OcfConfig.LOG_LEVEL))
            self.log_level = log_level_dict[OcfConfig.LOG_LEVEL]

ocf_config = OcfConfig()


def configure_log():
    log_format_vmmonitor = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_format_messages = "%(name)s - %(levelname)s - %(message)s"  # to avoid double timestamp in messages logs

    if ocf_config.log_level == ocf_config.LOG_LEVEL_OFF_VALUE:  # 100
        logging.disable(ocf_config.LOG_LEVEL_OFF_VALUE)
        logging.basicConfig(level=ocf_config.log_level)
        _log = logging.getLogger('ocfstatus')
        return _log

    _log = logging.getLogger('ocfstatus')

    try:
        vmmonitor_handler = logging.FileHandler(ocf_config.LOG_PATH)
        vmmonitor_formatter = logging.Formatter(log_format_vmmonitor)
        vmmonitor_handler.setFormatter(vmmonitor_formatter)
        vmmonitor_handler.setLevel(ocf_config.log_level)
        _log.addHandler(vmmonitor_handler)
    except IOError as ioe:
        _log.error(
            "Error opening log file [Errno %d] %s", ioe.errno, ioe.strerror)
        logging.basicConfig(level=ocf_config.log_level)
    try:
        messages_handler = logging.handlers.SysLogHandler(address='/dev/log')
        messages_formatter = logging.Formatter(log_format_messages)
        messages_handler.setFormatter(messages_formatter)
        messages_handler.setLevel(ocf_config.log_level)
        _log.addHandler(messages_handler)
    except IOError as ioe:
        _log.error(
            "Error opening syslog [Errno %d] %s", ioe.errno, ioe.strerror)
    return _log

log = configure_log()


def configure_ddclog():
    log_format_messages = "%(name)s: %(message)s"

    _log = logging.getLogger('DDCDATA')
    _log.setLevel(logging.INFO)

    try:
        messages_handler = logging.handlers.SysLogHandler(address='/dev/log',
                            facility=logging.handlers.SysLogHandler.LOG_LOCAL2)
        messages_formatter = logging.Formatter(log_format_messages)
        messages_handler.setFormatter(messages_formatter)
        _log.addHandler(messages_handler)
    except IOError as ioe:
        _log.error(
            "Error opening syslog [Errno %d] %s", ioe.errno, ioe.strerror)
    return _log


ddclog = configure_ddclog()


class ScriptRunner(object):
    def __init__(self):
        self.result = False
        self.has_nonexec = False
        self._previously_run_scripts = {}

    return_tuple = namedtuple(
        'Returned', 'return_code return_value time_taken')

    def find_scripts(self, script_path=ocf_config.script_path):
        try:
            list_entries = os.walk(script_path)
        except OSError as ose:
            log.error('%s:%d', ose.strerror, ose.errno)
            return []
        all_scripts = []
        for entry in sorted(list_entries, key=lambda x: x[0]):
            scripts = [os.path.join(entry[0], e) for e in entry[2]
                                                if not e.startswith('.')]
            for script in scripts:
                if not os.access(script, os.X_OK):
                    self.has_nonexec = True
                    log.error("Found non executable script: %s", script)
                    return []
            all_scripts.extend(sorted(scripts))  # list of files

        return all_scripts

    def run_all(self):
        all_scripts = self.find_scripts()
        result = []
        if self.has_nonexec:
            # Returns a positive code so that 503 is returned
            return (False, 1)
        start_time = time.time()
        qout = multiprocessing.Queue()
        workers = [multiprocessing.Process(
            target=self.run_with_timeout,
            args=(cmd, ocf_config.timeout, start_time, qout))
            for cmd in all_scripts]

        for worker in workers:
            worker.start()

        for worker in workers:
            worker.join()
            worker.terminate()
            result.append(qout.get())

        for res in result:
            if res["return_code"] != 0:
                return (False, res["return_code"])
        return True, None

    def run_with_timeout(self, command, timeout, start_time, qout):
        log.debug(
            "Running %s with timeout %s and start time %s",
            command, timeout, start_time)
        original_timeout = timeout
        pool_interval = 0.5
        is_shutdown = False
        is_request_timedout = False
        try:
            p = subprocess.Popen(
                [command, 'monitor'], close_fds=True, shell=False,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except OSError as ose:
            log.error('Error running %s - [Errno %d] %s',
                      command,
                      ose.errno, ose.strerror)
            return qout.put({
                "return_code": 1000,
                "return_value": None,
                "time_taken": original_timeout - timeout})

        while timeout > 0 and not is_request_timedout:
            if p.poll() is not None:
                result = (p.returncode, p.communicate())
                if result[0] != 0:
                    ddclog.info(
                        'Healthcheck_Status {"status":"Warning","summary":'
                        '"Healthcheck failed %s","summary_data":%d}',
                        os.path.basename(command), result[0])
                    log.warning(
                        "%s exited with status %d", command, result[0])
                    output = result[1][0].strip()
                    if output:
                        log.warning("script output: %s", result[1][0].strip())
                return qout.put({
                    "return_code": result[0],
                    "return_value": result[1],
                    "time_taken": original_timeout - timeout})
            if httpd_server and httpd_server.is_shutting_down():
                # break loop
                is_request_timedout = True
                is_shutdown = True
            timediff = time.time() - start_time
            log.debug("timediff: %s timeout: %s",
                      timediff, ocf_config.REQUEST_TIMEOUT)
            if timediff > ocf_config.REQUEST_TIMEOUT:
                ddclog.info(
                    'Healthcheck_Status {"status":"Monitor Timeout","summary":'
                    '"Healthcheck timeout %s","summary_data":%d}',
                    os.path.basename(command), ocf_config.REQUEST_TIMEOUT)
                log.warning(
                    "Killing %s: REQUEST TIMEOUT (%02d seconds) exceeded ",
                    command,
                    ocf_config.REQUEST_TIMEOUT)
                for res in self._previously_run_scripts:
                    log.warning(
                        "Previous successful script %s finished and "
                        "took %02d seconds",
                        res,
                        self._previously_run_scripts.get(res))
                try:
                    p.kill()
                except OSError as e:
                    if e.errno != 3:  # ESRCH No such process
                        # process is gone already
                        pass
                finally:
                    return qout.put({
                        "return_code": 504,
                        "return_value": None,
                        "time_taken": original_timeout - timeout})
            time.sleep(pool_interval)
            timeout -= pool_interval
        try:
            p.kill()
            if not is_shutdown:
                log.warning(
                    "Killing %s: timeout (%02d seconds) exceeded",
                    command, original_timeout)
            else:
                log.info("Killing %s: server shutdown", command)
                return qout.put({
                    "return_code": -1,
                    "return_value": None,
                    "time_taken": original_timeout - timeout})
        except OSError as e:
            if e.errno != 3:  # ESRCH No such process
                # process is gone already
                pass
        return qout.put({
            "return_code": 1000,
            "return_value": None,
            "time_taken": original_timeout - timeout})


class LITPHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

    def send_error(self, code, message=None):
        self.send_response(code, message)
        self.send_header("Content-Type", self.error_content_type)
        self.send_header('Connection', 'close')
        self.end_headers()
        self.connection.shutdown(socket.SHUT_RDWR)
        self.connection.close()

    def do_GET(self):
        path = self.path
        log.debug('do_GET conn fileno %d', self.connection.fileno())
        fileno = self.connection.fileno()
        log.debug('path = %s', path)
        path_noargs = path.split('?')
        if path_noargs[0] != '/':
            self.send_error(404)
            self.connection.close()
            return
        creation_time = conn_queue.socket_creation_time.get(fileno)
        if not creation_time:
            self.send_error(503)
            return

        result = ScriptRunner().run_all()
        if result[0]:
            self.send_response(200)
        else:
            if result[1] > 0:  # regular failure
                self.send_response(503)
            else:  # shutdown
                # socket is closed in the signal handler
                return
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', '0')
        self.end_headers()
        self.connection.close()

    def _clean_string(self, msg_raw):
        try:
            msg = "".join([c if (ord(c) < 128 and ord(c) > 31) else '?'\
                                                  for c in msg_raw])
        except TypeError:
            # if we can't clean the message, log it anyway
            msg = msg_raw
        return msg

    def log_request(self, code='-', size='-'):
        requestline = self._clean_string(self.requestline)
        log.debug('request "%s" %s %s',
                    requestline, str(code), str(size))

    def log_error(self, fmt, *args):
        log.debug(fmt, *args)


class HostIPFinderException(Exception):
    def __init__(self, msg=''):
        self.msg = msg
        super(HostIPFinderException, self).__init__()


class HostIPFinder(object):
    def __init__(self, port):
        self.port = port

    def get_ipv6_addr_iface(self, ip):
        # if our link ip begins with 'fe80'
        # this means it's a local link, hence
        # the interface must be specified
        log.info('Link level addr detected: %s', ip)
        addr_raw = socket.inet_pton(socket.AF_INET6, ip)
        full_addr = ''.join(['%2.2x' % ord(a) for a in addr_raw])
        all_links = open('/proc/net/if_inet6').readlines()
        ifl = [link for link in all_links if full_addr in link]
        if ifl:
            # get iface of first item
            iface = ifl[0].split()[-1]
            log.info("Interface of ipv6 monitor is: %s", iface)
        else:
            iface = None
            log.info("No interface found")
        return iface

    def get_full_ipv6_addr(self, ip):
        iface = self.get_ipv6_addr_iface(ip)
        if not iface:
            raise HostIPFinderException('Cannot find interface for %s' % (ip,))

        addr_info = socket.getaddrinfo('%s%%%s' % (ip, iface), self.port,
                            0, socket.AF_UNSPEC, socket.IPPROTO_TCP,
                            socket.AI_PASSIVE)
        return addr_info[0][4]

    def get_monitor_host(self, monitor_name):
        monitor_hosts = []
        port = self.port
        try:
            addr_info = socket.getaddrinfo(monitor_name, port, 0,
                                            0,
                                            socket.IPPROTO_TCP,
                                            socket.AI_PASSIVE)
            # the full info here is needed to listen
            listen_addrs = []
            for a in addr_info:
                ip_addr = a[4][0]
                if ip_addr == '::1':
                    continue
                if ip_addr == '127.0.0.1':
                    continue
                if ip_addr.lower().startswith('fe80'):
                    listen_info = self.get_full_ipv6_addr(ip_addr)
                    listen_addrs.append(listen_info)
                else:
                    listen_addrs.append(a[4])
            monitor_hosts.extend(listen_addrs)
        except socket.gaierror:
            # name does not resolve, ignore
            pass
        if not monitor_hosts:
            # :: will listen on the ipv4 address as well
            # however it will not show on netstat -l
            monitor_hosts.append(('::', port, 0, 0))
        return monitor_hosts

    def split_ip_per_type(self, ip_list):
        ip_family = {'ipv4': [], 'ipv6': []}
        for ip in ip_list:
            #pton doesn't know about ip%iface format
            ip_clean = ip[0].split('%')[0]
            v = self._get_ip_version(ip_clean)
            if v:
                ip_family[v].append(ip)
        return ip_family

    def _get_ip_version(self, ip):
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return 'ipv6'
        except socket.error:
            pass
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return 'ipv4'
        except socket.error:
            pass
        log.error("Unknown IP type for monitor address: %s", ip)
        return False

    def find_listen_ips(self):
        host_name = socket.gethostname()
        monitor_name = '%s-monitor' % (host_name,)
        log.debug("host name: %s", host_name)
        log.debug("monitor name: %s", monitor_name)
        monitor_hosts = self.get_monitor_host(monitor_name)
        monitor_hosts_ip = self.split_ip_per_type(monitor_hosts)
        log.debug("monitor_hosts = %s", monitor_hosts)
        return monitor_hosts_ip


class ConnExpireQueue(object):
    def __init__(self, max_size=128):
        self._incoming_queue = []
        self._queue_lock = threading.Semaphore()
        self.socket_creation_time = {}
        self._current = None
        self.max_size = max_size

    def append(self, request, client_address):
        now = time.time()
        log.debug('conn_queue %d %3.3f', request.fileno(), now)
        self.socket_creation_time[request.fileno()] = now
        self._queue_lock.acquire()
        self._incoming_queue.append((request, client_address, now))
        self._queue_lock.release()

    def get_next_request(self):
        try:
            self._queue_lock.acquire()
            if len(self._incoming_queue) == 0:
                return None
            req_raw = self._incoming_queue.pop(0)
            self._current = req_raw
        finally:
            self._queue_lock.release()
        return req_raw

    def can_append(self):
        if len(self._incoming_queue) >= self.max_size:
            return False
        return True

    def expire_items(self):
        new_iq = []
        expire_iq = []
        self._queue_lock.acquire()
        if len(self._incoming_queue) == 0:
            self._queue_lock.release()
            return None
        try:
            # lock already acquired here
            now = time.time()
            for req_raw in self._incoming_queue:
                log.debug("queue item %s", req_raw)
                req_time = req_raw[2]
                time_diff = (now - req_time)
                log.debug("time waiting diff %s", time_diff)
                if time_diff > ocf_config.REQUEST_TIMEOUT:
                    req = req_raw[:2]
                    log.debug('expiring fileno %d %3.6g',
                                        req[0].fileno(), time_diff)
                    expire_iq.append(req_raw)
                    # set to zero == expires the fileno
                    self.socket_creation_time[req[0].fileno()] = 0
                else:
                    new_iq.append(req_raw)
            self._incoming_queue = new_iq
        finally:
            self._queue_lock.release()
        return expire_iq

    def close_all(self):
        try:
            self._queue_lock.acquire()
            if self._current:
                try:
                    self._current[0].shutdown(socket.SHUT_RDWR)
                    self._current[0].close()
                    log.debug("Closed current connection")
                except socket.error:  # socket already close
                    pass
            log.debug("Closing %d connections on queue",
                                    len(self._incoming_queue))
            for conn in self._incoming_queue:
                try:
                    conn[0].shutdown(socket.SHUT_RDWR)
                    conn[0].close()
                except socket.error:  # socket already close
                    pass
            self._incoming_queue = []
        finally:
            self._queue_lock.release()


conn_queue = ConnExpireQueue()


class ConnProc(threading.Thread):
    def __init__(self, server, handle):
        self.__is_shut_down = threading.Event()
        self.server = server
        self._shutdown = False
        self.handle = handle
        super(ConnProc, self).__init__()

    def shutdown(self):
        self._shutdown = True
        self.__is_shut_down.wait()

    def run(self):
        handle = self.handle
        self.__is_shut_down.clear()
        try:
            while not self._shutdown:
                if handle == 'request':
                    self.server.handle_request_process()
                elif handle == 'expired':
                    self.server.handle_queue_expired()
                else:
                    raise Exception("handle should be 'request' or 'expired'")
                time.sleep(0.5)
        finally:
            self.__is_shut_down.set()


class TCPServerSplitQueue(SocketServer.TCPServer, object):
    allow_reuse_address = True
    request_queue_size = 128
    address_family = socket.AF_INET

    def __init__(self, _conn_queue, *a, **kw):
        self.__is_shut_down = threading.Event()
        self.__shutdown_request = False
        self.conn_queue = _conn_queue
        self.child_server = None
        super(TCPServerSplitQueue, self).__init__(*a, **kw)

    def create_child_ipv6_server(self, server_address):
        self.child_server = TCPServerSplitQueue6(self.conn_queue,
                                                 server_address,
                                                 self.RequestHandlerClass)
        return self.child_server

    def is_shutting_down(self):
        return self.__shutdown_request

    def shutdown(self):
        """Stops the serve_forever loop.

        Blocks until the loop has finished. This must be called while
        serve_forever() is running in another thread, or it will
        deadlock.
        """
        if self.child_server:
            self.child_server.shutdown()
        self.__shutdown_request = True
        self.__is_shut_down.wait()

    def handle_request_initial(self):
        if not self.conn_queue.can_append():
            return
        try:
            request, client_address = self.get_request()
        except socket.error:
            return
        self.conn_queue.append(request, client_address)

    def handle_queue_expired(self):
        expire_iq = conn_queue.expire_items()
        if not expire_iq:
            return
        for req_raw in expire_iq:
            req = req_raw[:2]
            self.handle_request_finish(*req)

    def handle_request_process(self):
        req_raw = self.conn_queue.get_next_request()
        if not req_raw:
            return
        req = req_raw[:2]
        if not self.is_shutting_down():
            self.handle_request_finish(*req)

    def handle_request_finish(self, request, client_address):
        if self.verify_request(request, client_address):
            try:
                fileno = request.fileno()
                self.process_request(request, client_address)
                self.conn_queue.socket_creation_time[fileno] = 0
            except socket.error as e:
                if e.errno == errno.EBADF:
                    # socket has been closed, there's nothing we can do
                    return
                self.handle_error(request, client_address)
                self.close_request(request)

    def serve_forever(self, poll_interval=0.5):
        log.debug('Starting serve_forever %s', self.__class__.__name__)
        self.__is_shut_down.clear()
        try:
            while not self.__shutdown_request:
                r, w, e = _eintr_retry(select.select, [self], [], [],
                                                            poll_interval)
                if self in r:
                    self.handle_request_initial()
                    log.debug('serve_forever loop %s', self.__class__.__name__)
        finally:
            self.__shutdown_request = False
            self.__is_shut_down.set()

    def handle_error(self, request, client_address):
        log.exception("Error handling request from %s", str(client_address))


class TCPServerSplitQueue6(TCPServerSplitQueue):
    address_family = socket.AF_INET6


def main(args):
    global exec_agents
    if '--exec_agents' in sys.argv:
        exec_agents = True
        log.debug("Executing OCF Resource Agents only")
        result = ScriptRunner().run_all()
        if result[0]:
            sys.exit(0)
        else:
            sys.exit(result[1])

    Handler = LITPHTTPRequestHandler
    try:
        listen_addr = HostIPFinder(ocf_config.port).find_listen_ips()
    except HostIPFinderException as e:
        log.error(e.msg)
        exit(3)

    listen_addr4 = listen_addr['ipv4']
    listen_addr6 = listen_addr['ipv6']
    httpd = None
    httpd6 = None
    listen_threads = []
    try:
        if listen_addr4:
            httpd = TCPServerSplitQueue(conn_queue,
                                       listen_addr4[0],
                                        Handler)
        if listen_addr4 and listen_addr6:
            httpd6 = httpd.create_child_ipv6_server(listen_addr6[0])

        elif listen_addr6:
            httpd6 = TCPServerSplitQueue6(conn_queue,
                                         listen_addr6[0],
                                         Handler)
    except socket.error as e:
        if e.errno in [98, 99]:
            err_msg = "Cannot listen on requested address:"
            if (httpd and listen_addr4) or not listen_addr4:
                # ipv4 worked or is not present
                err_msg += " %s " % (listen_addr6[0], )
            else:  # ipv4 failed
                err_msg += " %s " % (listen_addr4[0], )
            err_msg += "[Errno %d] %s" % (e.errno, e.strerror)
            sys.stderr.write(err_msg + '\n')
            log.critical(err_msg)
        else:
            import traceback
            err = traceback.format_exc()
            log.critical("Unknown error")
            log.critical(err)
            sys.stderr.write(err)
        sys.exit(2)

    if '--daemonize' in sys.argv:
        daemonize()

    global httpd_server
    httpd_server = httpd or httpd6
    try:
        pid = open(PID_FILE, 'w')
        pid.write(str(os.getpid()))
        pid.close()
    except (IOError, OSError) as e:
        log.error("Error writing PID file [Errno %d] %s", e.errno, e.strerror)
    if listen_addr4:
        log.debug("Listening at address %s:%d",
                                listen_addr4[0][0], ocf_config.port)
    if listen_addr6:
        log.debug("Listening at address %s:%d",
                                listen_addr6[0][0], ocf_config.port)

    if httpd:
        serve = threading.Thread(target=httpd.serve_forever,
                                        kwargs={'poll_interval': 0.5})
        serve.daemon = False
        serve.start()
        listen_threads.append(serve)

    if httpd6:
        serve6 = threading.Thread(target=httpd6.serve_forever,
                                        kwargs={'poll_interval': 0.5})
        serve6.daemon = False
        serve6.start()
        listen_threads.append(serve6)

    global conn_proc
    conn_proc = (ConnProc(httpd_server, 'request'),
                ConnProc(httpd_server, 'expired'))
    conn_proc[0].start()
    conn_proc[1].start()
    while listen_threads[0].isAlive():
        listen_threads[0].join(1)
    conn_proc[0].join(1)
    conn_proc[1].join(1)


if __name__ == '__main__':
    main(sys.argv)
