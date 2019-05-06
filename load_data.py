import configparser
import json
# Load the necessary data
def load_DBs():

    #load config file as library
    config = configparser.ConfigParser()
    config.read('./config_global.txt')
    if config.sections == []:
        print('configuration file not found\n')
        sys.exit(1)

    
    dsatable = dict()
    src2dsa = dict()
    dsa2cve = dict()
    cvetable = dict()
    src2month = dict()
    src2sloccount = dict()
    src2pop = dict()
    src2deps = dict()
    pkg_with_cvss = dict()
    src2cwe = dict()

    cache = config['DIR']['cache_dir']
    

    cache_dsatable = cache + 'dsatable'
    try:
        with open(cache_dsatable) as fp:
            dsatable = json.load(fp)
    except (IOError, ValueError):
        print('read cache dsatable failed!! Maybe first run of the system?')

    cache_src2dsa = cache + 'src2dsa'
    try:
        with open(cache_src2dsa) as fp:
            src2dsa = json.load(fp)
    except (IOError, ValueError):
        print('read cache src2dsa failed!! Maybe first run of the system?')

    cache_dsa2cve = cache + 'dsa2cve'
    try:
        with open(cache_dsa2cve) as fp:
            dsa2cve = json.load(fp)
    except (IOError, ValueError):
        print('read cache dsa2cve failed!! Maybe first run of the system?')

    cache_cvetable = cache + 'cvetable'
    try:
        with open(cache_cvetable) as fp:
            cvetable = json.load(fp)
    except (IOError, ValueError):
        print('read cache cvetable failed!! Maybe first run of the system?')

    cache_src2deps = cache + 'src2deps'
    try:
        with open(cache_src2deps) as fp:
            src2deps = json.load(fp)
    except (IOError, ValueError):
        print('read cache src2deps failed!! Maybe first run of the system?')


    cache_src2month = cache + 'src2month'
    try:
        with open(cache_src2month) as fp:
            src2month = json.load(fp)
    except (IOError, ValueError):
        print('read cache src2month failed!! Maybe first run of the system?')
    
    cache_pkg_with_cvss = cache + 'pkg_with_cvss'
    try:
        with open(cache_pkg_with_cvss) as fp:
            pkg_with_cvss = json.load(fp)
    except (IOError, ValueError):
        print('read cache pkg_with_cvss failed!! Maybe first run of the system?')
    
    cache_src2sloccount = cache + 'src2sloccount'
    try:
        with open(cache_src2sloccount) as fp:
            src2sloccount = json.load(fp)
    except (IOError, ValueError):
        print('read cache src2sloccount failed!! Maybe first run of the system?')
    
    cache_src2pop = cache + 'src2pop'
    try:
        with open(cache_src2pop) as fp:
            src2pop = json.load(fp)
    except (IOError, ValueError):
        print('read cache src2pop failed!! Maybe first run of the system?')
    
    src2cwe = cache + 'src2cwe'
    try:
        with open(src2cwe) as fp:
            src2cwe = json.load(fp)
    except (IOError, ValueError):
        print('read cache src2cwe failed!! Maybe first run of the system?')
    
    return(dsatable, src2dsa, dsa2cve, cvetable, src2month, src2sloccount, src2pop, src2deps, pkg_with_cvss, src2cwe)
