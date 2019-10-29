#!/usr/bin/python3
from DebianAdvisory import DebianAdvisory as da
from CVEParse import CVEParse as cveparse
import re
import datetime
from html.parser import HTMLParser
from bs4 import BeautifulSoup
from bs4 import NavigableString
from pymongo import MongoClient
import urllib.request
import logging, sys
import pickle
import json
from fixcwes import ret_roots


def getDLAs():

    src2monthDLAs = dict()
    totalDLAs = dict()
    totalDLAsList = []

    base_url = 'https://lists.debian.org/debian-lts-announce/'

    logging.info('Checking for DLAs...\n')

    dlas = []

    more = True
    i = 0
    j = 0

    for year in range(2014,2020):
        for month in range(1,13):
            totalDLAs[str(year) + ',' + str(month)] = []
            i = 0
            while more:
                try:
                    url = base_url + str(year) + '/' + str(month).zfill(2) + '/msg' + str(i).zfill(5) + '.html'
                    print('Opening url: ' + url + '\n')
                    req = urllib.request.urlopen(url)
                    charset = req.info().get_content_charset()
                    if charset is None:
                        charset = 'utf-8'
                        dla = req.read().decode(charset)
                        dlas.append([dla, year, month])
                        
                        p1 = re.compile('Package.*: .*')
                        p2 = re.compile('CVE-[0-9]{4}-[0-9]*')
                        (pkg, cves) = parseDLAhtml(dla, p1, p2)
                        pkg = fixURL(url, pkg)
                        try:
                            pkg = da.unifySrcName(pkg)
                        except AttributeError:
                            print('Problem with')
                            print(pkg)
                            print('#'*80)

                        if pkg:
                            totalDLAs[str(year) + ',' + str(month)] += cves
                            try:
                                src2monthDLAs[pkg].append((cves, [year,month]))
                            except KeyError:
                                src2monthDLAs[pkg] = []
                                src2monthDLAs[pkg].append((cves, [year,month]))

                except urllib.error.HTTPError as err:
                    if (i>1):
                        break
                i+=1
            
            print(totalDLAs[str(year) + ',' + str(month)])
            totalDLAs[str(year) + ',' + str(month)] = list(set(totalDLAs[str(year) + ',' + str(month)]))
            totalDLAsList.append(len(totalDLAs[str(year) + ',' + str(month)]))
            j += 1

    print(totalDLAs)
    print(totalDLAsList)

    with open("DLA_sum.txt","wb") as fp:
        pickle.dump(totalDLAsList,fp)
    
    with open("src2month_DLA.txt","wb") as fp:
        pickle.dump(src2monthDLAs,fp)
    
    with open("src2month_DLA.json","w") as fp:
        json.dump(src2monthDLAs,fp)

    return(totalDLAsList)

def permonthDLA(src2monthDLAs):
    client = MongoClient()
    out = dict()
    out_cvss = dict()
    out_cwe = dict()
    for pkg in src2monthDLAs:
        (out[pkg], out_cvss[pkg], out_cwe[pkg]) = perPackage(pkg, src2monthDLAs[pkg], out, out_cvss, client)
        #out_cwe[pkg] = perPackage_cwe(pkg, src2monthDLAs[pkg])
        with open("DLA_src2month.json","w") as fp:
            json.dump(out,fp)
        
        with open("DLA_withcvss.json","w") as fp:
            json.dump(out_cvss,fp)
        #
        with open("DLA_withcwe.json","w") as fp:
            json.dump(out_cwe,fp)

def perPackage(pkg, dlas, cvss, out, client): 
    root_list = ['682', '118', '330', '435', '664', '691', '693', '697', '703', '707', '710' ]
    monthyear = []
    monthyear_cvss = []
    monthyear_cwe = []
    haveseen = dict()
    for i in range(2000,2019):
        temp = []
        temp_cvss = []
        temp_cwe = []
        for j in range(12):
            temp.append(0)
            temp_cvss.append([0,0,0,0])
            temp_cwe.append([0]*12)
        monthyear.append(temp)
        monthyear_cvss.append(temp_cvss)
        monthyear_cwe.append(temp_cwe)
    
    for dla in dlas:
        for cve_id in dla[0]:
            if cve_id in haveseen:
                continue
            else:
                haveseen[cve_id] = 1
            cve = cveparse.fetchCVE(cve_id, client)
            (cve_date, cve_base, cve_impact, cve_exploit, cwe) = cveparse.parseCVE(cve_id, cve)
            new_year = dla[1][0]
            new_month = dla[1][1]
            if (cve_date.year<new_year) or (cve_date.year==new_year and cve_date.month<new_month):
                new_year=cve_date.year
                new_month=cve_date.month
            try:
                cve_base = float(cve_base)
            except TypeError:
                cve_base = -1.0
            monthyear[new_year-2000][new_month-1] += 1
            if (cve_base < 0.0):
                monthyear_cvss[new_year-2000][new_month-1][3] += 1
            elif (cve_base < 4.0):
                monthyear_cvss[new_year-2000][new_month-1][0] += 1
            elif (cve_base < 7.0):
                monthyear_cvss[new_year-2000][new_month-1][1] += 1
            else:
                monthyear_cvss[new_year-2000][new_month-1][2] += 1
            
            for i in ret_roots(cwe):
                if i == 0:
                    monthyear_cwe[new_year-2000][new_month-1][11] += 1
                    print('Problem with cve: ', cve_id)
                    continue
                for j in range(len(root_list)):
                    if i == root_list[j]:
                        monthyear_cwe[new_year-2000][new_month-1][j] += 1

    return(monthyear, monthyear_cvss, monthyear_cwe)


def parseDLAhtml(dla, p1, p2):
    
    pkg = re.search(p1, dla)

    if pkg:
        print(pkg.group(0))
        pkg = pkg.group(0).split(':',1)[1].strip()
        # Deal witg the different versions also here...
        pkg=da.unifySrcName(pkg)
        print(pkg)
    else:
        print(dla)
    
    cves = re.findall(p2, dla)
    cves = list(set(cves))

    
    return (pkg, cves)

def fixURL(url, pkg):
    if (url=='https://lists.debian.org/debian-lts-announce/2016/10/msg00011.html'):
        return 'mpg123'
    elif (url=='https://lists.debian.org/debian-lts-announce/2016/05/msg00037.html'):
        return 'graphicsmagick'
    else:
        return pkg

if __name__== "__main__":
  dlas = getDLAs()