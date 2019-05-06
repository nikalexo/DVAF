from load_data import load_DBs
from pymongo import MongoClient
import datetime
import random
import laplace as lp
import matplotlib.pyplot as plt
import paper_plots as carlosplt
import numpy as np
import json

class Mydata:
    def __init__(self, load):
        if load:
            (self.dsatable, self.src2dsa, self.dsa2cve, self.cvetable, self.src2month, self.src2sloccount, self.src2pop, self.src2deps, self.pkg_with_cvss) = load_DBs()
        else:
            print('no load command given')


def main():
    vlist = []
    carlosplt.pre_paper_plot() 
    fig = plt.figure()    
    tester = calc_laplace()
    ax = fig.add_subplot(2,2,1)    
    tester.laplace_php([])
    ax = fig.add_subplot(2,2,2)    
    tester.laplace_openjdk([])
    ax = fig.add_subplot(2,2,3)    
    tester.laplace_wheezy([], False)
    ax = fig.add_subplot(2,2,4)    
    tester.laplace_wheezy([], True)
    carlosplt.post_paper_plot(True,True,True)
    plt.show()

class calc_laplace:
    def __init__(self):
        i = 0

    def getDLAdates(self):
        pass

    def calculate(self):
        pass

    def laplace_php(self, vlist):
        try:
            with open("php5.json", "r") as fp:
                new_vlist = json.load(fp)
        except:
            new_vlist = vlist
            with open("php5.json", "w") as fp:
                json.dump(new_vlist,fp)

        print(len(new_vlist))
        year_start = 7
        self.laplace_process_list(new_vlist[12*year_start:-6], 'php5', year_start)

    def laplace_openjdk(self, vlist):
        try:
            with open("openjdk.json", "r") as fp:
                new_vlist = json.load(fp)
        except:
            new_vlist = vlist
            with open("openjdk.json", "w") as fp:
                json.dump(new_vlist,fp)
        print(len(new_vlist))
        year_start = 13
        self.laplace_process_list(new_vlist[12*year_start+6:], 'openjdk-7', year_start)

    def laplace_wheezy(self, vlist, high):
        (dsatable, src2dsa, dsa2cve, cvetable, src2month, src2sloccount, src2pop, src2deps, pkg_with_cvss, src2cwe) = load_DBs()
        print(len(src2month['linux']))
        if not high:
            with open("DLA_src2month.json", "r") as fp:
                dlas = json.load(fp)
        else:
            src2month = pkg_with_cvss
            with open("DLA_withcvss.json", "r") as fp:
                dlas = json.load(fp)

        total = [0]*len(src2month['linux'])
        for pkg in src2month:
            for month in range(len(src2month[pkg])):
                if high:
                    total[month] += src2month[pkg][month][2]
                else:
                    total[month] += src2month[pkg][month]

        total_dla = [0]*(len(dlas['linux'])*12)
        print(total_dla)
        for pkg in dlas:
            for year in range(len(dlas[pkg])):
                for month in range(len(dlas[pkg][year])):
                    if high:
                        total_dla[year*12+month] += dlas[pkg][year][month][2]
                    else:
                        total_dla[year*12+month] += dlas[pkg][year][month]
        print(total)
        print(total_dla)
        dsa_wheezy = total[12*13 + 4: 12*16 + 3]
        dla_wheezy = total_dla[-12*3 + 4:-7]
        print(len(dsa_wheezy))
        print(len(dla_wheezy))

        wheezy = dsa_wheezy + dla_wheezy
        print(len(wheezy))

        if not high:
            self.laplace_process_list(wheezy, 'wheezy', 13)
        else:
            self.laplace_process_list(wheezy, 'wheezy-high', 13)

    def laplace_package(self, pkg):
        pass

    def laplace_process_list(self,vlist, pkg, year):
        months = len(vlist)
        print(pkg)
        perhour = 24*30*months
        instances = []
        laplace_values = []
        i = 0
        print(pkg)
        print(vlist)
        for month in vlist:
            i += 1
            temp = random.sample(range(24*30*(i-1),24*30*i),month)
            instances += temp
            laplace_values.append(lp.laplace_test(instances, 24*30*i))

        final_laplace = lp.laplace_test(instances, 24*30*i+1)
        print(final_laplace)

        n = len(vlist)
        if pkg == 'wheezy':
            x = range(n+12)
        else:
            x = range(n)
        print(n)
        yearsx = ['\''+str(year+2000+i)[-2:] for i in range(len(vlist)//12+1)]
        carlosplt.post_paper_plot(True,True,True)

        #print(x)
        if pkg == 'wheezy':
            plt.plot(x,[None]*4+laplace_values+[None]*8)#
        else:
            plt.plot(x,laplace_values)
        plt.axhline(y=1.96, linestyle = ':', color = 'orange')
        plt.axhline(y=2.33, linestyle = ':', color = 'red')
        plt.axhline(y=-1.96, linestyle = ':', color = 'orange')
        plt.axhline(y=-2.33, linestyle = ':', color = 'red')
        plt.xticks(np.arange(0, n, step=12), yearsx)
        plt.ylabel(pkg)        



if __name__ == "__main__":
    main()
