'''
rastrea2r client
'''
import sys
import os
import logging
from logging.handlers import RotatingFileHandler
import configparser

__version__ = '0.1.0'

# Initialize Configuration
config = configparser.ConfigParser()
config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), '../rastrea2r', 'rastrea2r.ini'))

ENABLE_TRACE = config["rastrea2r"]["enable_trace"]
AUTH_USER = config["rastrea2r"]["username"]
AUTH_PASSWD = config["rastrea2r"]["password"]
SERVER_PORT = config["rastrea2r"]["server_port"]
CLIENT_VERSION = config["rastrea2r"]["version"]
API_VERSION = config["rastrea2r"]["api_version"]
WINDOWS_COMMANDS = config["rastrea2r"]["windows_commands"].split(',')


# Check for sane config file
if "rastrea2r" not in config:
    print("Could not parse config file")
    sys.exit(1)

# Logging Configuration, default level INFO
logger = logging.getLogger("")
logger.setLevel(logging.INFO)
lformat = logging.Formatter("%(asctime)s %(name)s:%(levelname)s: %(message)s")

# Debug mode Enabled
if "debug" in config["rastrea2r"] and int(config["rastrea2r"]["debug"]) != 0:
    debug = int(config["rastrea2r"]["debug"])
    logger.setLevel(logging.DEBUG)
    logging.debug("Enabled Debug mode")
else:
    # STDOUT Logging defaults to Warning
    lsh = logging.StreamHandler(sys.stdout)
    lsh.setFormatter(lformat)
    lsh.setLevel(logging.WARNING)
    logger.addHandler(lsh)

# Enable logging to file if configured
if "logfile" in config["rastrea2r"]:
    lfh = RotatingFileHandler(
        config["rastrea2r"]["logfile"], maxBytes=(1048576 * 5), backupCount=3
    )
    lfh.setFormatter(lformat)
    logger.addHandler(lfh)
