import configparser
import json
import datetime
import logging
from pymongo import MongoClient
import numpy as np
import os
from dateutil import parser

from .DebianAdvisory import DebianAdvisory
from .CVEParse import CVEParse
from ..VendorModel import VendorModel
from .CSVReader import CSVReader
from .Tests import Tests
from fixcwes import ret_roots

class DebianModel(VendorModel):
    """
    This class represents M-Star debian module. It is responsible for handling debian package infos.
    """
    module_path = os.path.dirname(__file__)


    def __init__(self, action, configfile=os.path.join(module_path, 'config_default.txt')):
        ## DBs to track
        """
        TODO: Tables to manage.
        """
        self.dsatable = dict()
        self.src2dsa = dict()
        self.dsa2cve = dict()
        self.cvetable = dict()
        self.src2month = dict()
        self.src2sloccount = dict()
        self.src2pop = dict()
        self.src2deps = dict()
        self.pkg_with_cvss = dict()
        self.src2sum = dict()
        self.src2monthDLA = dict()
        self.pkg_with_cvss_DLA = dict()
        self.src2cwe = dict()


        ## config
        self.configfile = configfile
        self.config = configparser.ConfigParser()
        if not self.config.read(configfile):
            raise IOError('Cannot open configuration file: ')
        (self.state, self.err) = self.load_state()

        self.client = MongoClient()

        if action == 'update':
            self.load_dbs()
            self.update_dbs()
            self.store_dbs()
            self.save_state(self.state)
            # lstm.predict(src2month, src2sloccount, src2pop, src2deps)
            """
            with open('dsatable.txt', 'w') as file:
                file.write(str(sorted(self.dsatable.keys(), key=lambda x: str(x).lower())))
            with open('src2dsa.txt', 'w') as file:
                file.write(str(sorted(self.src2dsa.keys(), key=lambda x: str(x).lower())))
            with open('dsa2cve.txt', 'w') as file:
                file.write(str(sorted(self.dsa2cve.keys(), key=lambda x: str(x).lower())))
            with open('cvetable.txt', 'w') as file:
                file.write(str(sorted(self.cvetable.keys(), key=lambda x: str(x).lower())))
            with open('src2month.txt', 'w') as file:
                file.write(str(sorted(self.src2month.keys(), key=lambda x: str(x).lower())))
            with open('src2sloccount.txt', 'w') as file:
                file.write(str(sorted(self.src2sloccount.keys(), key=lambda x: str(x).lower())))
            with open('src2pop.txt', 'w') as file:
                file.write(str(sorted(self.src2pop.keys(), key=lambda x: str(x).lower())))
            with open('src2deps.txt', 'w') as file:
                file.write(str(sorted(self.src2deps.keys(), key=lambda x: str(x).lower())))
                """
        elif action == 'status':
            self.load_dbs()
            # aptsec_status(sys.argv[2])
        elif action == 'show':
            self.load_dbs()
            self.store_dbs()
        else:
            self.print_help(self)

    def get_src2month(self):
        return self.src2month

    def get_vendor_dir(self):
        return self.module_path

    def load_dbs(self):
        """
        Loads the required databases into the model. Can either be implemented as read from file, or read from DB.
        Currently reading it from files in the cache folder.
        """
        self.dsatable = self.load_single_db_from_cache('dsatable')
        self.src2dsa = self.load_single_db_from_cache('src2dsa')
        self.dsa2cve = self.load_single_db_from_cache('dsa2cve')
        self.cvetable = self.load_single_db_from_cache('cvetable')
        self.src2deps = self.load_single_db_from_cache('src2deps')
        self.src2month = self.load_single_db_from_cache('src2month')
        self.src2sloccount = self.load_single_db_from_cache('src2sloccount')
        self.src2pop = self.load_single_db_from_cache('src2pop')
        self.pkg_with_cvss = self.load_single_db_from_cache('pkg_with_cvss')
        self.src2monthDLA = self.load_single_db_from_cache('src2monthDLA')
        self.pkg_with_cvss_DLA = self.load_single_db_from_cache('pkg_with_cvss_DLA')
        self.src2cwe = self.load_single_db_from_cache('src2cwe')

    def load_single_db_from_cache(self, file_name):
        cache_dir = os.path.join(self.module_path, self.config['DIR']['cache_dir'])
        try:
            with open(os.path.join(cache_dir, file_name)) as f:
                return json.load(f)
        except (IOError, ValueError):
            print('Read cache ' + file_name + ' failed!! Maybe first run of the system?')
            return dict()

    def store_dbs(self):
        self.store_db_single('dsatable', self.dsatable)
        self.store_db_single('src2dsa', self.src2dsa)
        self.store_db_single('dsa2cve', self.dsa2cve)
        self.store_db_single('cvetable', self.cvetable)
        self.store_db_single('src2deps', self.src2deps)
        self.store_db_single('src2sloccount', self.src2sloccount)
        self.store_db_single('src2pop', self.src2pop)
        self.store_db_single('pkg_with_cvss', self.pkg_with_cvss)
        self.store_db_single('src2monthDLA', self.src2monthDLA)
        self.store_db_single('pkg_with_cvss_DLA', self.pkg_with_cvss_DLA)
        self.store_db_single('src2cwe', self.src2cwe)

        # src2month needs special handling
        # Check later if the same is true for other dicts
        cache_src2month = os.path.join(self.module_path, self.config['DIR']['cache_dir'], 'src2month')
        int_list = dict()

        for element in self.src2month:
            for i in range(len(self.src2month[element])):
                if element in int_list:
                    int_list[element].append(int(self.src2month[element][i]))
                else:
                    int_list[element] = []
                    int_list[element].append(int(self.src2month[element][i]))
        try:
            with open(cache_src2month, 'w') as fp:
                json.dump(int_list, fp, default=self.converter)
        except IOError:
            print('write cache src2month failed!! Fatal error')

    def store_db_single(self, file_name, db):
        cache_dir = os.path.join(self.module_path, self.config['DIR']['cache_dir'])
        try:
            with open(os.path.join(cache_dir, file_name), 'w') as f:
                json.dump(db, f, default=self.converter)
        except (IOError, ValueError):
            print('Read cache ' + file_name + ' failed!! Maybe first run of the system?')

    def save_state(self, state):
        """Save state, different from DBs in that we always need it"""
        state_file = os.path.join(self.module_path, self.config['DIR']['cache_dir'], 'state')
        try:
            with open(state_file, 'w') as sf:
                json.dump(state, sf)
        except IOError:
            print('Write cache state failed!! Fatal error')

    def converter(self, o):
        """Help for save_DBs"""
        if isinstance(o, datetime.datetime) or isinstance(o, datetime.timedelta):
            return str(o)
        if isinstance(o, np.float):
            return o.astype(int)

    def update_dbs(self):
        now = datetime.datetime.now()
        new_adv = DebianAdvisory.checkDSAs(self.state, self.config)

        for id in new_adv:
            if id in self.dsatable:
                logging.info(self.state['vendor'] + ' advisory ' + id + ' already known.\n')
            else:
                ## store advisory and parse it
                self.dsatable[id] = new_adv[id]
                self.updateCVETables(id)

        # recompute all pkg statistics
        for srcpkg in self.src2dsa:
            self.processCVEs(srcpkg, now)

    def updateCVETables(self, myid):

        logging.info('Updating vulnerability database with advisory ' + self.state['vendor'] + str(myid) + ' \n')

        adv = self.dsatable[myid]
        dsastats = DebianAdvisory.parseDSAhtml(adv)

        dsastats = DebianAdvisory.fixDSAquirks(myid, dsastats)

        for srcpkg in dsastats[0]:
            if srcpkg in self.src2dsa:
                self.src2dsa[srcpkg].append(myid)
            else:
                self.src2dsa[srcpkg] = []
                self.src2dsa[srcpkg].append(myid)

            self.dsa2cve[str(myid)] = dsastats[2]


        for cve_id in dsastats[2]:
            # No fetch CVE We use mongodb and cve-search
            cve = CVEParse.fetchCVE(cve_id, self.client)
            cvestats = CVEParse.parseCVE(cve_id, cve)
            finaldate = cvestats[0]

            if cvestats[0] > dsastats[1] or cvestats[0] == 0:
                finaldate = dsastats[1]

            self.cvetable[cve_id] = (finaldate, dsastats[1] - finaldate, cvestats[1], cvestats[2], cvestats[3], cvestats[4])

    def load_state(self):
        """
        Load state, different from DBs in that we always need it.
        Retrieves the cached state for current configuration.
        :return:  state , error number
        """
        state_file = os.path.join(self.module_path, self.config['DIR']['cache_dir'], 'state')
        err = 0

        try:
            with open(state_file) as json_data:
                state = json.load(json_data)
        except FileNotFoundError:
            # Load default state - start from the beginning
            print('File not found in: ' + state_file)
            print('Loading default state.')
            state = dict()
            state['cache_dir'] = 'cache/'
            state['vendor'] = 'debian'
            state['next_adv'] = 0
            state['next_fsa'] = 0
            state['Packages'] = ''
            state['Sources'] = ''
            state['Sha1Sums'] = ''
            err += 1

        return state, err

    def processCVEs(self, srcpkg, now):

        stats = [now, 0, 0, 0, 0, 0, 0]
        cvestats = dict()
        logging.info('Processing package: ' + srcpkg + '.\n')

        ## keep track of the number of low-medium-high severity vulnerabilities
        ## TODO see how cvss affects vulnerability prediction - if some packages show patterns
        with_cvss = dict()
        ## Keep track of the vulnerability types
        with_cwe = dict()
        root_list = ['682', '118', '330', '435', '664', '691', '693', '697', '703', '707', '710' ]

        ## To eliminate duplicate cves
        haveseen = dict()

        ## cvestats = (date: number)
        for dsa_id in self.src2dsa[srcpkg]:
            for cve_id in self.dsa2cve[str(dsa_id)]:
                if cve_id in haveseen:
                    continue
                else:
                    haveseen[cve_id] = 1
                    tt = self.cvetable[cve_id][0]
                    if tt in cvestats:
                        cvestats[tt] += 1
                    else:
                        cvestats[tt] = 1
            stats[1] += 1

        haveseen = dict()
        haveseen2 = dict()

        ## with_cvss = (date: number low, number med, number high, number undefined)
        for dsa_id in self.src2dsa[srcpkg]:
            for cve_id in self.dsa2cve[str(dsa_id)]:
                tt = self.cvetable[cve_id][0]
                try:
                    temp_cvss = float(self.cvetable[cve_id][2])
                except TypeError:
                    print(cve_id)
                    continue

                if cve_id in haveseen:
                    continue
                else:
                    haveseen[cve_id] = 1
                    if tt in with_cvss:
                        if (temp_cvss < 0.0):
                            with_cvss[tt][3] += 1
                        elif (temp_cvss < 4.0):
                            with_cvss[tt][0] += 1
                        elif (temp_cvss < 7.0):
                            with_cvss[tt][1] += 1
                        else:
                            with_cvss[tt][2] += 1
                    else:
                        with_cvss[tt] = [0, 0, 0, 0]
                        if (temp_cvss < 0.0):
                            with_cvss[tt][3] += 1
                        elif (temp_cvss < 4.0):
                            with_cvss[tt][0] += 1
                        elif (temp_cvss < 7.0):
                            with_cvss[tt][1] += 1
                        else:
                            with_cvss[tt][2] += 1

        ## with_cwe = (date: 11*[root type])
        for dsa_id in self.src2dsa[srcpkg]:
            for cve_id in self.dsa2cve[str(dsa_id)]:
                tt = self.cvetable[cve_id][0]
                try:
                    temp_cwe = self.cvetable[cve_id][5]
                except TypeError:
                    print(cve_id)
                    continue

                if cve_id in haveseen2:
                    continue
                else:
                    haveseen2[cve_id] = 1
                    if tt in with_cwe:
                        for i in ret_roots(temp_cwe):
                            if i == 0:
                                with_cwe[tt][11] += 1
                                print('Problem with cve: ', cve_id)
                            for j in range(len(root_list)):
                                if i == root_list[j]:
                                    with_cwe[tt][j] += 1
                    else:
                        with_cwe[tt] = [0]*12
                        for i in ret_roots(temp_cwe):
                            if i == 0:
                                with_cwe[tt][11] += 1
                                print('Problem with cve: ', cve_id)
                            for j in range(len(root_list)):
                                print('This is the with_cwe')
                                if i == root_list[j]:
                                    with_cwe[tt][j] += 1
                                    print('This is the with_cwe')
                                    print(with_cwe)

        # Ignore pkgs with less than one incident, should not happen..
        if stats[1] < 1:
            return

        dates = sorted(cvestats, key=cvestats.get)
        try:
            stats[0] = dates[0]
        except IndexError:
            print(srcpkg + str(dates))
            stats[0] = 0

        count = sum(cvestats.values())

        self.format_data(srcpkg, with_cvss, self.pkg_with_cvss, True)

        self.format_data(srcpkg, cvestats, self.src2month, False)

        self.format_cwes(srcpkg, with_cwe)

#########################################################################
    def format_cwes(self, srcpkg, with_cwe):
        x = []
        y = []
        monthyear = []
        year = []

        temp_items = list(with_cwe.items())
        items = []

        for cwe_dict in temp_items:
            if isinstance(cwe_dict[0], str):
                tmpx = (parser.parse(cwe_dict[0]))
            else:
                tmpx = cwe_dict[0]
            x.append(tmpx)
            
            tmpy = cwe_dict[1]
            
            y.append(tmpy)
            items.append((tmpx, tmpy))

        items.sort(key=lambda tup: tup[0])

        for i in range(2000,2020):
            temp = []
            for j in range(12):
                temp.append([0]*12)
            monthyear.append(temp)

        for i in range(len(x)):
            for j in range(len(y[i])):
                monthyear[x[i].year - 2000][x[i].month - 1][j] += y[i][j]

        months_list = [item for sublist in monthyear for item in sublist]

        self.src2cwe[srcpkg] = months_list



    def format_data(self, pkg, cvestats, src2temp, cvss):
        x = []
        y = []
        monthyear = []
        year = []

        temp_items = list(cvestats.items())
        items = []

        for data_dict in temp_items:
            if isinstance(data_dict[0], str):
                tmpx = (parser.parse(data_dict[0]))
            else:
                tmpx = data_dict[0]
            x.append(tmpx)

            try:
                tmpy = int(data_dict[1])
            except TypeError:
                tmpy = data_dict[1]
            y.append(tmpy)
            items.append((tmpx, tmpy))

        items.sort(key=lambda tup: tup[0])

        for i in range(2000, 2020):
            temp = []
            for j in range(12):
                if cvss:
                    temp.append([0, 0, 0, 0])
                else:
                    temp.append(0)
            monthyear.append(temp)

        for i in range(len(x)):
            if cvss:
                tmp0 = y[i][0]
                tmp1 = y[i][1]
                tmp2 = y[i][2]
                tmp3 = y[i][3]
                monthyear[x[i].year - 2000][x[i].month - 1][0] += tmp0
                monthyear[x[i].year - 2000][x[i].month - 1][1] += tmp1
                monthyear[x[i].year - 2000][x[i].month - 1][2] += tmp2
                monthyear[x[i].year - 2000][x[i].month - 1][3] += tmp3
            else:
                monthyear[x[i].year - 2000][x[i].month - 1] += y[i]

        months_list = [item for sublist in monthyear for item in sublist]

        if not cvss:
            temp_months = np.zeros(len(months_list))
            i = 0
            for element in months_list:
                temp_months[i] = np.float32(element)
                i += 1

            src2temp[pkg] = temp_months
        else:
            src2temp[pkg] = months_list

        return

    def unifySrcName(self, name):
        return DebianAdvisory.unifySrcName(name)

    def performTests(self):
        #Tests.system_input_prediction_error_test(self)
        #Tests.random_input_prediction_error_test(self)
        Tests.relativity_of_expectations_test(self)

    def load_latest_prediction_model(self):
        return CSVReader.read_csv_prediction_errorcompl(os.path.join(self.module_path, 'models', 'latest_model.csv'), self, 9)

    def gen_model_opinion_set(self, filename, month, norm_param):
        """
        Generates opinion set from the model input.
        :param filename: model (package:prediction:errorcompl:f)
        :param month: month parameter of the model
        :param norm_param: normalization factor of the model
        :return: dictionary of opinions
        """
        res = CSVReader.read_csv_prediction_errorcompl(filename, self, month, norm_param=norm_param)
        # with open('vendors/debian/models/dummy_model_' + str(month) + '.csv', 'w') as file:
        #    for key in res:
        #        file.write(key + ":" + str(res[key].t) + ":" + str(res[key].c) + ":" + str(res[key].f) + "\n")
        return res


    @staticmethod
    def print_help():
        """
        Prints help message to this vendor model.
        """
        print("Debian mstar model supports only update status and show actions.")







