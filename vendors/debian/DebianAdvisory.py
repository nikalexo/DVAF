import logging
import datetime
import os
import re
import urllib.request
from bs4 import BeautifulSoup
from bs4 import NavigableString


class DebianAdvisory:

    @staticmethod
    def checkDSAs(state, config):
        """Try to find new DSAs by iteration, return table of DSAs to process"""
        dsatable = dict()
        next_dsa = int(state['next_adv'])
        # state implemented as dictionary
        base_url = config['URL']['dsa_base_url']

        logging.info('Checking for new DSAs.. \n')

        if next_dsa < int(config['DSA']['first_dsa']):
            logging.debug('Cache was deleted, starting at DSA ' + str(next_dsa) + '\n')
            next_dsa = int(config['DSA']['first_dsa'])

        next_dsa2string = '%03d' % next_dsa

        blacklist = map(str.strip, config['DSA']['blacklist'].split(','))
        #print('Blacklist ', list(blacklist))
        #print(blacklist)
        blacklist = list(blacklist)
        if DebianAdvisory.blacklistedDSA('DSA-' + next_dsa2string, blacklist):
            next_dsa += 1

        dsa = DebianAdvisory.fetchDSA(next_dsa, base_url)


        while dsa != '':
            logging.debug('Got DSA-' + str(next_dsa) + '\n')
            soup = BeautifulSoup(dsa, 'html.parser')
            # crop the DSA from unecessary weight
            dsa = soup.find(id="content")
            if dsa == '':
                raise NameError('html file format unexpected')
            dsatable[next_dsa] = str(dsa)
            next_dsa += 1
            if DebianAdvisory.blacklistedDSA('DSA-' + str(next_dsa), list(blacklist)):
                next_dsa += 1
            dsa = DebianAdvisory.fetchDSA(next_dsa, base_url)

        state['next_adv'] = next_dsa
        return dsatable

    @staticmethod
    def blacklistedDSA(dsa_id, blacklist):
        """Should this advisory be skipped?"""
        if dsa_id in blacklist:
            return True
        else:
            return False

    @staticmethod
    def fetchDSA(dsa_id, base_url):
        """Fetches a given dsa from the url."""
        year = 2000
        now = datetime.datetime.now()
        current_year = now.year

        logging.info('Fetching DSA-%d records\n', dsa_id)

        if dsa_id >= 4078:
            year = 2018
        elif dsa_id >= 3751:
            year = 2017
        elif dsa_id >= 3431:
            year = 2016
        elif dsa_id >= 3118:
            year = 2015
        elif dsa_id >= 2832:
            year = 2014
        elif dsa_id >= 2597:
            year = 2013
        elif dsa_id >= 2377:
            year = 2012
        elif dsa_id >= 2140:
            year = 2011
        elif dsa_id >= 1965:
            year = 2010
        elif dsa_id >= 1694:
            year = 2009
        elif dsa_id >= 1443:
            year = 2008
        elif dsa_id >= 1245:
            year = 2007
        elif dsa_id >= 929:
            year = 2006
        elif dsa_id >= 622:
            year = 2005
        elif dsa_id >= 406:
            year = 2004
        elif dsa_id >= 220:
            year = 2003
        elif dsa_id >= 96:
            year = 2002
        elif dsa_id >= 11:
            year = 2001

        dsa_id2string = '%03d' % dsa_id

        flag = True
        while flag:
            try:
                flag = False
                logging.info('Opening url: ' + base_url + str(year) + '/dsa-' + dsa_id2string + '\n')
                req = urllib.request.urlopen(base_url + str(year) + '/dsa-' + dsa_id2string)
                charset = req.info().get_content_charset()
                if charset is None:
                    charset = 'utf-8'
                dsa = req.read().decode(charset)
                return dsa
            except urllib.error.HTTPError as err:
                if year < current_year:
                    year += 1
                    flag = True
                else:
                    dsa = ''
                    return dsa

    @staticmethod
    def parseDSAhtml(dsa):
        dsa_names = []
        dsa_CVEs = []
        # Date Reported -> dsa_date
        soup = BeautifulSoup(dsa, 'html.parser')
        tmp = soup.find("dt", string=re.compile(".*Date Repo.*:"))
        tmp = str(tmp.find_next().contents[0])
        # dsa_date = tmp.split()
        # date in datetime python format
        dsa_date = datetime.datetime.strptime(tmp, "%d %b %Y")
        if not dsa_date:
            print('Unable to extract date. Raising exception...')
            raise NameError('DSA parsing problem!')

        # Affected Packages -> dsa_names
        # print(dsa)
        tmp = soup.find("dt", string=re.compile("Affected Packages:"))
        tmp = tmp.find_next().contents
        # Need to check with multiple vulnerable packages
        for i in tmp:
            if (not isinstance(i, NavigableString)) and i.has_attr('href'):
                # greedy 'and' operation assumed
                unified = DebianAdvisory.unifySrcName(i.string)
                dsa_names.append(unified)
                pass
        if not dsa_names:
            print('Unable to find src package in DSA. unnamed package...')
            dsa_names.append('unnamed')
            print('Unnamed dsa:' + str(dsa) + '\n')

        # Security database references (CVEs) -> dsa_CVEs
        tmp = soup.find("dt", string=re.compile("Security database references:"))
        tmp = tmp.find_next().descendants
        for i in tmp:
            if (not isinstance(i, NavigableString)) and i.has_attr('href'):
                # don't count bug database
                if not re.compile("^Bug*").match(i.string):
                    dsa_CVEs.append(i.string)

        return dsa_names, dsa_date, dsa_CVEs

    @staticmethod
    def unifySrcName(name):
        """Track renamed packages here, easy but manual. We should look into ways to automate this
        TODO: it should map to the most recent version, not unversioned
        TODO: we can partially automate this..
        make all lower-case
        replace -X.Y version numbers by highest encounter(?)
        handle special cases like xfree86
        """
        lowername = name.lower()
        suf = os.path.join(os.path.dirname(__file__), 'src_name_unifications.txt')
        with open(suf) as su:
            for line in su:
                sp_line = line.strip().split("->")
                if re.compile(sp_line[0]).match(name):
                    return sp_line[1]
        return name

    @staticmethod
    def fixDSAquirks(dsa_id, dsa_state):
        """
        TODO:
        Static map to correct errors in DSAs
        Return fixed list of CVE IDs or 0 to skip DSA
        This code is still experimental
        """
        new_names = dsa_state[0]
        new_date = dsa_state[1]
        new_cves = dsa_state[2]

        if dsa_id == 85:
            new_cves = ["CVE-2001-1562", "LOCAL-03/04/05", "LOCAL-08/24/08"]
        elif dsa_id == 745:
            newcves = ["CVE-2005-1921", "CVE-2005-2106", "CVE-2005-1921"]
        elif dsa_id == 1095:
            new_cves = ["CVE-2006-0747", "CVE-2006-1861", "CVE-2006-2661"]
        elif dsa_id == 1284:
            new_cves = ["CVE-2007-1320", "CVE-2007-1321", "CVE-2007-1322", "CVE-2007-2893", "CVE-2007-1366"]
        elif dsa_id == 1502:
            new_cves = ["CVE-2007-2821", "CVE-2007-3238", "CVE-2008-0193", "CVE-2008-0194"]
        elif dsa_id == 1706:
            new_cves = ["CVE-2009-0135", "CVE-2009-0136"]
        elif dsa_id == 1757:
            new_cves = ["CVE-2007-2383", "CVE-2008-7220", "CVE-2009-1208"]
        elif dsa_id == 1896:
            new_cves = ["CVE-2009-3474", "CVE-2009-3475", "CVE-2009-3476"]
        elif dsa_id == 1931:
            new_cves = ["CVE-2009-0689", "CVE-2009-2463"]
        elif dsa_id == 1989:
            new_cves = ["CVE-2010-0789"]
        elif dsa_id == 1941:
            new_cves = ["CVE-2009-0755", "CVE-2009-3903", "CVE-2009-3904", "CVE-2009-3905", "CVE-2009-3606",
                        "CVE-2009-3607", "CVE-2009-3608", "CVE-2009-3909", "CVE-2009-3938"]
        elif dsa_id == 2004:
            new_cves = ["CVE-2010-0787", "CVE-2010-0547"]
        elif dsa_id == 2008:
            new_cves = ["LOCAL-02/23/10", "LOCAL-02/23/10", "LOCAL-02/23/10", "LOCAL-02/23/10"]
        elif dsa_id == 2043:
            new_cves = ["CVE-2010-2062"]
        elif dsa_id == 2044:
            new_cves = ["CVE-2010-2062"]
        elif dsa_id == 2056:
            new_cves = ["CVE-2010-2155", "CVE-2009-4882"]
        elif dsa_id == 2092:
            new_cves = ["CVE-2010-1625", "CVE-2010-1448", "CVE-2009-4497"]
        elif dsa_id == 2098:
            new_cves = ["CVE-2010-3659", "CVE-2010-3660", "CVE-2010-3661", "CVE-2010-3662", "CVE-2010-3663",
                        "CVE-2010-3664", "CVE-2010-3665", "CVE-2010-3666", "CVE-2010-3667", "CVE-2010-3668",
                        "CVE-2010-3669", "CVE-2010-3670", "CVE-2010-3671", "CVE-2010-3672", "CVE-2010-3673",
                        "CVE-2010-3674"]
        elif dsa_id == 2103:
            new_cves = ["CVE-2010-3076"]
        elif dsa_id == 2218:
            new_cves = ["CVE-2011-1684"]
        elif dsa_id == 2229:
            new_cves = ["CVE-2005-4494", "CVE-2006-0517", "CVE-2006-0518", "CVE-2006-0519", "CVE-2006-0625",
                        "CVE-2006-0626", "CVE-2006-1295", "CVE-2006-1702", "CVE-2007-4525", "CVE-2008-5812",
                        "CVE-2008-5813", "CVE-2009-3041"]
        elif dsa_id == 2261:
            new_cves = ["CVE-2009-4078", "CVE-2009-4079", "CVE-2009-4059", "LOCAL-12/30/10", "LOCAL-12/30/10"]
        elif dsa_id == 2262:
            new_cves = ["LOCAL-03/01/11", "LOCAL-03/01/11", "LOCAL-03/01/11", "LOCAL-03/01/11", "LOCAL-05/18/11",
                        "LOCAL-05/18/11"]
        elif dsa_id == 2286:
            new_names = ["phpmyadmin"]
        elif dsa_id == 1977:
            new_names = ["python3.5"]
        elif (
                                    dsa_id == 47 or dsa_id == 479 or dsa_id == 480 or dsa_id == 482 or dsa_id == 489 or dsa_id == 491 or dsa_id == 495):
            new_names = ["linux"]
            print('Substitution successful')
        elif dsa_id == 2289:
            new_cves = ["LOCAL-07/27/11", "LOCAL-07/27/11", "LOCAL-07/27/11", "LOCAL-07/27/11", "LOCAL-07/27/11",
                        "LOCAL-07/27/11", "LOCAL-07/27/11", "LOCAL-07/27/11", "LOCAL-07/27/11", "LOCAL-07/27/11",
                        "LOCAL-07/27/11", "LOCAL-07/27/11"]

        return new_names, new_date, new_cves
