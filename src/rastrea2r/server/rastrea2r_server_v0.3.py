#!/usr/bin/env python
#
# rastrea2r REST Server
#
# by Ismael Valenzuela @aboutsecurity / Foundstone (Intel Security)


from time import gmtime, strftime
from bottle import route, get, run, post, request
import socket

__author__ = 'ismael.valenzuela@foundstone.com'
__version__ = '0.3'

""" Variables """

server_address = '0.0.0.0'  # Bind to all interfaces
server_port = 8080  # Default REST server port


@post('/getrule')
def index():
    """ Method to serve a yara rule to the REST client. Rulename (filename) must exist on the same directory """

    rulename = request.forms.get('rulename')
    print ("\nPulling " + rulename + "\n")
    try:
        f = open(rulename, 'rb')
        rule = f.read()
        f.close()
        return rule
    except:
        print ("\nError: The rule requested doesn't exist\n")


@post('/putfile')
def index():
    """ Method to post client data from file/dir scan to the REST server. Timestamps written in GMT """

    recivedt = strftime('%Y-%m-%d %H:%M:%S', gmtime())
    rulename = request.forms.get('rulename')
    filename = request.forms.get('filename')
    hostname = request.forms.get('hostname')
    module = request.forms.get('module')

    try:
        f = open("results.txt", "a")
        f.write("%s, %s, %s, %s, %s\n\n" % (recivedt, hostname, rulename, module, filename))
        f.close()
    except IOError:
        print ("\nError: The output file requested doesn't exist\n")
    return""


@post('/putpid')
def index():
    """ Method to post client data from process memory scan to the REST server. Timestamps written in GMT """

    recivedt = strftime('%Y-%m-%d %H:%M:%S', gmtime())
    rulename = request.forms.get('rulename')
    processpath = request.forms.get('processpath')
    processpid = request.forms.get('processpid')
    hostname = request.forms.get('hostname')
    module = request.forms.get('module')

    try:
        f = open("results.txt", "a")
        f.write("%s, %s, %s, %s, %s, %s\n\n" % (recivedt, hostname, rulename, module, processpath, processpid))
        f.close()
    except IOError:
        print ("\nError: The output file requested doesn't exist\n")
    return""


run(host=server_address, port=server_port)
