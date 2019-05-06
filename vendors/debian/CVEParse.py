import logging, sys
import re
import datetime


class CVEParse:
    """
    Functions for downloading and parsing Common Vulnerability DB data.
    """
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

    @staticmethod
    def correctCVE(cve_id):
        cve_id_new = cve_id
        if cve_id == 2116:
            cve_id_new = 1921

        return cve_id_new

    @staticmethod
    def fetchCVE(cve_id, client):
        """
        Get details of given CVE entry from NIST DB - we use cve-search and mongodb
        """
        logging.info('Fetching CVE: ' + cve_id + '\n')

        # Make this subtitution for some reason
        cve_id = re.sub('^CAN', 'CVE', cve_id)
        cve_id = CVEParse.correctCVE(cve_id)
        ##
        ## get CVE Scores from db
        ##
        db = client.cvedb
        collection = db.cves
        cve = collection.find_one({"id": cve_id})

        if cve == '':
            logging.warning('CVE not found in mongodb')
        return cve


        # Check for error pages: referenced but unpublished CVEs :-/


    @staticmethod
    def parseCVE(cve_id, cve):
        """
        Get CVE severity rating and report date, and return
        (date base-score impact-score exploit-score)
        """
        # use -1 as defaults (meaning not reported yet)
        cve_date = datetime.datetime.now()
        cve_base = -1
        cve_impact = -1
        cve_exploit = -1
        cwe = 0

        try:
            if cve == None:
                print('CVE' + str(cve_id) + ' not yet reported, getting default value -1')
                return (cve_date, cve_base, cve_impact, cve_exploit, cwe)
            else:
                cve_date = cve['Published']
                cve_base = cve['cvss']
                cwe = cve['cwe']
        except KeyError:
            print('CVE ' + cve_id + ' not parsed correctly')

        return (cve_date, cve_base, cve_impact, cve_exploit, cwe)
