#!/usr/bin/python3
import logging
import sys

from vendors.debian.DebianModel import DebianModel

##### GLOBAL VARIABLES #####
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

# Increase the recursion limit by much to allow bs to parse large files ()
sys.setrecursionlimit(6000)

secondsperday = 86400
verbosity = 1

###### FUNCTIONS ######


def aptsec_help():
    """
    :return:
    """
    print('See manual for correct usage!')


def __main__(configfile='config_default.txt', vendorname='debian', action='help'):
    # support only debian
    if vendorname is 'debian':
        model = DebianModel(action)

        #lstm.predict(model.get_src2month(),{},{},{})

        #for norm_param in range(1, 15):
        # get model as set of opinions


    else:
        print("Only debian vendors are supported for now.")
        sys.exit(1)

__main__(action=sys.argv[1])
