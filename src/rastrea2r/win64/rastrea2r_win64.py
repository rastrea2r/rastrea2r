#!/usr/bin/env python
#
# rastrea2r win 64 client
#

import os
import psutil  # New multiplatform library
import subprocess
import yara
from argparse import ArgumentParser
from requests import post
from time import gmtime, strftime
from requests.auth import HTTPBasicAuth
from utils import http_utils
from rastrea2r import ENABLE_TRACE, AUTH_USER, AUTH_PASSWD, SERVER_PORT, CLIENT_VERSION, API_VERSION
import json
import traceback
import logging


__version__ = CLIENT_VERSION

logger = logging.getLogger(__name__)


def yaradisk(path, server, rule, silent):
    """ Yara file/directory object scan module """

    results = []
    rule_url = server + ":" + SERVER_PORT + API_VERSION + "/rule?rulename=" + rule
    logger.debug("Rule_URL:"+rule_url)
    rule_text = http_utils.http_get_request(url=rule_url, auth=HTTPBasicAuth(AUTH_USER, AUTH_PASSWD))

    if not silent:
        logger.debug('\nPulling ' + rule + ' from ' + server + '\n')
        logger.debug(rule_text + '\n')
        logger.debug('\nScanning ' + path + '\n')

    rule_bin = yara.compile(sources={'namespace': rule_text})

    for root, dirs, filenames in os.walk(path):
        for name in filenames:
            try:
                file_path = os.path.join(root, name)
                matches = rule_bin.match(filepath=file_path)

                if matches:
                    result = {"rulename": matches[0],
                              "filename": file_path,
                              "module": 'yaradisk',
                              "hostname": os.environ['COMPUTERNAME']}
                    if not silent:
                        logger.debug(result)

                    results.append(result)

            except Exception as e:
                logging.error(
                    "Exception when executing yara-disk ERROR: {error}, TRACE: {stack_trace}".format(
                        error=str(e), stack_trace=traceback.format_exc() if ENABLE_TRACE else ""))

    if len(results) > 0:
        headers = {'module': 'yara-disk-scan',
                   'Content-Type': 'application/json'}
        results_url = server + ":" + SERVER_PORT + API_VERSION + '/results'
        response = http_utils.http_post_request(url=results_url, body=json.dumps(results),
                                                auth=HTTPBasicAuth(AUTH_USER, AUTH_PASSWD),
                                                headers=headers)

        if response.status_code == 200:
            logger.info("yara-disk Results pushed to server successfully")
        else:
            logger.error("Error uploading the results: " + response.text)

    else:
        logger.info("No matches found!!!")


def yaramem(server, rule, silent):
    """ Yara process memory scan module """

    results = []
    rule_url = server + ":" + SERVER_PORT + API_VERSION + "/rule?rulename=" + rule
    logger.debug("Rule_URL:"+rule_url)
    rule_text = http_utils.http_get_request(url=rule_url, auth=HTTPBasicAuth(AUTH_USER, AUTH_PASSWD))

    if not silent:
        logger.debug('\nPulling ' + rule + ' from ' + server + '\n')
        logger.debug(rule_text + '\n')
        logger.debug('\nScanning running process in Memory \n')

    mypid = os.getpid()

    rule_bin = yara.compile(source=rule_text)

    for process in psutil.process_iter():
        try:
            pinfo = process.as_dict(attrs=['pid', 'name', 'exe', 'cmdline'])
        except psutil.NoSuchProcess:
            pass
        else:
            if not silent:
                logger.debug(pinfo)

        client_pid = pinfo['pid']
        client_pname = pinfo['name']
        client_ppath = pinfo['exe']
        client_pcmd = pinfo['cmdline']

        if client_pid != mypid:
            try:
                matches = rule_bin.match(pid=client_pid)
            except:
                if not silent:
                    print('Failed scanning process ID: %d' % client_pid)
                continue

            if matches:
                result = {"rulename": matches,
                          "processpath": client_ppath,
                          "processpid": client_pid,
                          "module": 'yaramem',
                          "hostname": os.environ['COMPUTERNAME']}
                if not silent:
                    logger.debug(result)

                results.append(result)

    if len(results) > 0:
        headers = {'module': 'yara-mem-scan',
                   'Content-Type': 'application/json'}
        results_url = server + ":" + SERVER_PORT + API_VERSION + '/results'
        response = http_utils.http_post_request(url=results_url, body=json.dumps(results),
                                                auth=HTTPBasicAuth(AUTH_USER, AUTH_PASSWD),
                                                headers=headers)

        if response.status_code == 200:
            logger.info("yara-mem Results pushed to server successfully")
        else:
            logger.error("Error uploading the results: " + response.text)

    else:
        logger.info("No matches found!!!")


def memdump(tool_server, output_server, silent):
    """ Memory acquisition module """

    smb_bin = tool_server + r'\tools'  # TOOLS Read-only share with third-party binary tools
    smb_data = output_server + r'\data'  # DATA Write-only share for output data

    tool = ('winpmem -')  # Sends output to STDOUT

    fullcommand = tool.split()
    commandname = fullcommand[0].split('.')

    recivedt = strftime('%Y%m%d%H%M%S', gmtime())  # Timestamp in GMT

    f = open(r'\\' + smb_data + r'\\' + recivedt + '-' + os.environ['COMPUTERNAME'] + '-' + commandname[0] + '.img',
             'w')

    if not silent:
        print('\nDumping memory to ' + r'\\' + smb_data + r'\\' + recivedt + '-' + os.environ['COMPUTERNAME'] + '-'
              + commandname[0] + '.img\n')

    pst = subprocess.call(r'\\' + smb_bin + r'\\' + tool, stdout=f)


def triage(tool_server, output_server, silent):
    """ Triage collection module """

    smb_bin = tool_server + r'\tools'  # TOOLS Read-only share with third-party binary tools
    smb_data = output_server + r'\data'  # DATA Write-only share for output data

    """ Add your list of Sysinternal / third-party / BATCH files here """

    tool = ('psloggedon.exe /accepteula',
            'autorunsc.exe -a * -ct -h /accepteula',
            'netstat.bat')

    """ BATCH files must be called with the .bat extension """

    for task in tool:  # Iterates over the list of commands

        fullcommand = task.split()
        commandname = fullcommand[0].split('.')

        recivedt = strftime('%Y%m%d%H%M%S', gmtime())  # Timestamp in GMT

        f = open(r'\\' + smb_data + r'\\' + recivedt + '-' + os.environ['COMPUTERNAME'] + '-' + commandname[0] + '.log',
                 'w')

        if not silent:
            logger.debug('\nSaving output of ' + task + ' to ' + r'\\' + smb_data + r'\\' + recivedt + '-' + os.environ[
                'COMPUTERNAME']
                + '-' + commandname[0] + '.log\n')

        pst = subprocess.call(r'\\' + smb_bin + r'\\' + task, stdout=f)


def main():
    parser = ArgumentParser(description='::Rastrea2r RESTful remote Yara/Triage tool for Incident Responders '
                                        'by Ismael Valenzuela @aboutsecurity / Foundstone (Intel Security)::')

    subparsers = parser.add_subparsers(dest="mode", help='modes of operation')

    """ Yara filedir mode """

    list_parser = subparsers.add_parser('yara-disk', help='Yara scan for file/directory objects on disk')
    list_parser.add_argument('path', action='store', help='File or directory path to scan')
    list_parser.add_argument('server', action='store', help='rastrea2r REST server')
    list_parser.add_argument('rule', action='store', help='Yara rule on REST server')
    list_parser.add_argument('-s', '--silent', action='store_true', help='Suppresses standard output')

    """Yara memory mode"""

    list_parser = subparsers.add_parser('yara-mem', help='Yara scan for running processes in memory')
    list_parser.add_argument('server', action='store', help='rastrea2r REST server')
    list_parser.add_argument('rule', action='store', help='Yara rule on REST server')
    list_parser.add_argument('-s', '--silent', action='store_true', help='Suppresses standard output')

    """Memory acquisition mode"""

    list_parser = subparsers.add_parser('memdump', help='Acquires a memory dump from the endpoint')
    list_parser.add_argument('BIN_server', action='store', help='Binary tool server (SMB share)')
    list_parser.add_argument('DATA_server', action='store', help='Data output server (SMB share)')
    list_parser.add_argument('-s', '--silent', action='store_true', help='Suppresses standard output')

    """Triage mode"""

    list_parser = subparsers.add_parser('triage', help='Collects triage information from the endpoint')
    list_parser.add_argument('BIN_server', action='store', help='Binary tool server (SMB share)')
    list_parser.add_argument('DATA_server', action='store', help='Data output server (SMB share)')
    list_parser.add_argument('-s', '--silent', action='store_true', help='Suppresses standard output')

    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)
    args = parser.parse_args()

    if args.mode == 'yara-disk':
        yaradisk(args.path, args.server, args.rule, args.silent)

    elif args.mode == 'yara-mem':
        yaramem(args.server, args.rule, args.silent)

    elif args.mode == 'memdump':
        memdump(args.BIN_server, args.DATA_server, args.silent)

    elif args.mode == 'triage':
        triage(args.BIN_server, args.DATA_server, args.silent)


if __name__ == '__main__':
    main()
