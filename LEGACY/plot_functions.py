import paper_plots as carlosplt
import stat_tests as stats
import matplotlib.pyplot as plt
import numpy as np
import pickle
import vendors.debian.DLAmine as dla
import json
import csv
from matplotlib.font_manager import FontProperties
import seaborn as sns
import laplace_tests as lptests
import statsmodels.api as sm


class Plotter:
    def __init__(self, src2month, src2sloccount, pkg_with_cvss, years):
        self.src2month = src2month
        self.src2sloccount = src2sloccount
        self.pkg_with_cvss = pkg_with_cvss
        self.years = years
        self.src2month_temp = dict()
        self.src2month_loc = dict()
        self.l=self.m=self.h=self.udef=0

    def plot_severity_percentage(self):
        num_low = [0] * (self.years+1)
        num_med = [0] * (self.years+1)
        num_high = [0] * (self.years+1)
        num_udef = [0] * (self.years+1)
        total = [0] * (self.years+1)
        for i in self.pkg_with_cvss:
            for j in range(len(self.src2month[i])):
                try:
                    num_low[j//12] += self.pkg_with_cvss[i][j][0]
                    num_med[j//12] += self.pkg_with_cvss[i][j][1]
                    num_high[j//12] += self.pkg_with_cvss[i][j][2]
                    num_udef[j//12] += self.pkg_with_cvss[i][j][3]
                    total[j//12] += self.pkg_with_cvss[i][j][3] + self.pkg_with_cvss[i][j][2] + self.pkg_with_cvss[i][j][1] + self.pkg_with_cvss[i][j][0]
                except IndexError:
                    xx = j//12
                    if xx==19:
                        continue
                    else:
                        print(xx)
                        #raise IndexError('List index out of bounds')
                    
        ## Generate percentage
        for i in range(self.years + 1):
            try:
                num_low[i] = num_low[i]/total[i]
                num_med[i] = num_med[i]/total[i]
                num_high[i] = num_high[i]/total[i]
                num_udef[i] = num_udef[i]/total[i]
            except ZeroDivisionError:
                num_low[i] = 0
                num_med[i] = 0
                num_high[i] = 0
                num_udef[i] = 0

        print(num_low)
        print(num_high)


        carlosplt.pre_paper_plot()        

        pal = ['#fee8c8', '#fdbb84', '#e34a33', 'grey']
        x = range(2001, 2001 + self.years)

        labels_cvss = ['low', 'medium', 'high', 'N/A']

        h = plt.stackplot(x, [num_low[1:], num_med[1:], num_high[1:], num_udef[1:]], colors = pal, alpha=0.9, labels = labels_cvss)
        plt.xticks(x)
        plt.legend(loc='upper left', handles = h[::-1])
        carlosplt.post_paper_plot(True,True,True)
        plt.show()

    
    ## Plot sum of vulnerabilities. Can filter out by severity using the booleans low, med, high, undefined
    def plot_all_severity(self, l, m, h, udef):
        carlosplt.pre_paper_plot()
        self.l = l
        self.m = m
        self.h = h
        self.udef = udef
        for i in self.pkg_with_cvss:
            self.src2month_temp[i]=[]
            for j in range(len(self.src2month[i])):
                num_low = self.pkg_with_cvss[i][j][0]
                num_med = self.pkg_with_cvss[i][j][1]
                num_high = self.pkg_with_cvss[i][j][2]
                num_udef = self.pkg_with_cvss[i][j][3]
                tempp = 0
                if l:
                    tempp += num_low
                if m:
                    tempp += num_med
                if h:
                    tempp += num_high
                if udef:
                    tempp += num_udef
                self.src2month_temp[i].append(tempp)

        for i in self.src2month:
            self.src2month_loc[i]=self.src2month_temp[i][:] # don't cut data for 2018

        self.severityPlotter = Temp_Plotter(self)
        self.severityPlotter.plot_total()

        # Plot total number per year
        self.pkgnumPlotter = NumPackages_Plotter(self.severityPlotter)
        
        # Plot number of affected packages per year
        self.pkgnumPlotter.plot_num_affected()
        
        # Plot average number of vulnerabilities per affected package per year
        self.pkgnumPlotter.plot_average_number()

        # Plot regular and LTS for Wheezy
        self.wheezy = WheezyPloter(self)
        self.wheezy.plot_wheezy_lts()


class Temp_Plotter:
    def __init__(self, plotter):
        self.src2month = plotter.src2month
        self.src2sloccount = plotter.src2sloccount
        self.pkg_with_cvss = plotter.pkg_with_cvss
        self.years = plotter.years
        self.src2month_loc = plotter.src2month_loc

        self.src2sum = dict()
        self.src2year = dict()
        self.src2lastyears = dict()
        self.src2dens = dict()
        self.src2month_temp = dict()
        self.year_sum = []
        self.year_num = []

    def plot_total(self):
        self.year_sum = [0] * self.years
        self.year_num = [0] * self.years
        for pkg in self.src2month_loc:
            for j in range(self.years):
                temp =  sum(self.src2month_loc[pkg][12*(1+j):12*(2+j)])
                if (temp>0):
                    self.year_num[j] += 1
                self.year_sum[j] += temp 
            ## For last 2 years
            total = sum(self.src2month_loc[pkg][:])
            last_years = sum(self.src2month_loc[pkg][-24:])
            #print(pkg + '; ' + str(last_years))
            if (total>1):
                self.src2sum[pkg] = total
                self.src2lastyears[pkg] = last_years
        
        #calc total
        sum_total = 0
        one_only=0
        one_plus=0
        for p in self.src2month:
            sum_part = sum(self.src2month_loc[p][:])
            sum_total += sum_part
            if (sum_part == 1):
                one_only += 1
            elif (sum_part>1):
                one_plus += 1

        print('Total = ', sum_total)
        print('one_only = ', one_only)
        print('one_plus = ', one_plus)

        values = sorted(self.src2sum.values(),reverse=True)
        #print(values)
        keys = list(sorted(self.src2sum, key=self.src2sum.__getitem__, reverse=True))

        n = len(self.year_sum)
        yearsx = []
        for i in range(1,self.years+1):
            if i%2==1:
                yearsx.append('\''+str(i).zfill(2))
            else:
                yearsx.append('')
        x = range(self.years)

        width = 1/2
        plt.bar(x, self.year_sum, width, color='darkblue', edgecolor='black')
        #plt.bar(x, average_per_year, width)
        plt.xticks(np.arange(0,n),yearsx)
        plt.ylabel('Total vulnerabilities')
        plt.xlabel('Year')
        carlosplt.post_paper_plot(True,True,True)
        
        sum_all = sum(values)
        print("Total: ", sum_all)

        ## Linear regression model
        X = sm.add_constant(x)
        y = self.year_sum
        model = sm.OLS(y,X).fit()
        predictions = model.predict(X)
        plt.plot(predictions)
        plt.show()
        print(model.summary())
        print(model.summary().as_latex())

class NumPackages_Plotter:
    def __init__(self, plotter):
        self.plotter = plotter
        self.yearsx = []

    def plot_num_affected(self):
        ## Number of affected packages
        n = len(self.plotter.year_sum)
        for i in range(1,self.plotter.years+1):
            if i%2==1:
                self.yearsx.append('\''+str(i).zfill(2))
            else:
                self.yearsx.append('')
        x = range(self.plotter.years)
        width = 1/2
        plt.bar(x, self.plotter.year_num, width, color='darkblue', edgecolor='black')
        plt.xticks(np.arange(0,n),self.yearsx)
        plt.ylabel('Number of affected packages')
        plt.xlabel('Year')
        carlosplt.post_paper_plot(True,True,True)
        plt.show()

    def plot_average_number(self):
        average_per_year = [0] * self.plotter.years
        for j in range(self.plotter.years):
            average_per_year[j] = self.plotter.year_sum[j]/float(self.plotter.year_num[j])
        
        x_values = list(range(1,self.plotter.years+1))
        slope = np.polyfit(x_values,average_per_year,1)
        
        print('Slope: ' + str(slope))
        
        n = len(self.plotter.year_sum)
        x = range(self.plotter.years)
        width = 1/2
        #plt.bar(x, year_sum, width)
        plt.bar(x, average_per_year, width, color='darkblue', edgecolor='black')
        plt.xticks(np.arange(0,n),self.yearsx)
        plt.ylabel('Average vulnerabilities per package')
        plt.xlabel('Year')
        carlosplt.post_paper_plot(True,True,True)
        ## Linear regression
        X = sm.add_constant(x)
        y = average_per_year
        model = sm.OLS(y,X).fit()
        predictions = model.predict(X)
        plt.plot(predictions)
        plt.show()
        print(model.summary())
        print(model.summary().as_latex())

class WheezyPloter:
    def __init__(self, plotter):
        self.plotter = plotter
        self.yearsx = []
        self.l = plotter.l
        self.m = plotter.m
        self.h = plotter.h
        self.udef = plotter.udef


    def plot_wheezy_lts(self):
        quarter_num = self.plotter.years*4
        # Get LTS and plot
        try:
            with open("DLA_sum.txt","rb") as fp:
                ltslist = pickle.load(fp)
            with open("src2month_DLA.txt","rb") as fp:
                src2monthDLAs = pickle.load(fp)
            with open("DLA_src2month.json","r") as fp:
                src2monthDLA = json.load(fp)
            with open("DLA_withcvss.json","r") as fp:
                self.src2monthDLA_cvss = json.load(fp)
                # Fix this so it can compute when required
                #dla.permonthDLA(src2monthDLAs)
            with open("1000.csv","r") as csvfile:
                spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')

        except IOError:
            ltslist = dla.getDLAs()
            with open("src2month_DLA.txt","rb") as fp:
                src2monthDLAs = pickle.load(fp)
            dla.permonthDLA(src2monthDLAs)
            return self.plot_wheezy_lts()
        
        ## Plot for wheezy
        quarter_sum = [0] * quarter_num

        DLA_temp=dict()
        
        ## Fix src2monthDLA_cvss
        for i in self.src2monthDLA_cvss:
            temp_list = []
            for j in self.src2monthDLA_cvss[i]:
                temp_list += j
            self.src2monthDLA_cvss[i] = temp_list

        ## Fix ltslist according to severity
        for i in self.src2monthDLA_cvss:
            DLA_temp[i]=[]
            for j in range(len(self.src2monthDLA_cvss[i])):
                num_low = self.src2monthDLA_cvss[i][j][0]
                num_med = self.src2monthDLA_cvss[i][j][1]
                num_high = self.src2monthDLA_cvss[i][j][2]
                num_udef = self.src2monthDLA_cvss[i][j][3]
                tempp = 0
                if self.l:
                    tempp += num_low
                if self.m:
                    tempp += num_med
                if self.h:
                    tempp += num_high
                if self.udef:
                    tempp += num_udef
                DLA_temp[i].append(tempp)

        
        ltslist = []

        for m in range((self.plotter.years+1)*12):
            s = 0
            #print(m)
            for i in DLA_temp:
                s += DLA_temp[i][m]
            ltslist.append(s)


        totalLTS = ltslist
        plt.bar([i for i in range(len(ltslist))],ltslist)
        plt.show()

        quartersx = []
        for i in range(1,self.plotter.years+1):
            for j in range(1,5):
                if j==1:
                    quartersx.append('Q' + str(j)+'\''+str(i).zfill(2))
                else:
                    quartersx.append(' ')
    
        for pkg in self.plotter.src2month_loc:
            for j in range(quarter_num):
                temp =  sum(self.plotter.src2month_loc[pkg][12+(3*j):12+3*(j+1)])
                quarter_sum[j] += temp 

        LTS_quarter = []
    
        for j in range(quarter_num):
            temp = sum(totalLTS[12+(3*j):12+3*(j+1)])
            LTS_quarter.append(temp)

        ## Print all LTS
        cut = 12*4+1
        n = len(quarter_sum)
        x = range(quarter_num)
        width = 1/2

        plt.bar(x, LTS_quarter, width, color='brown', label='regular support', edgecolor='black')
    
        plt.xticks(np.arange(0,n),quartersx, rotation="vertical")
        plt.ylabel('Vulnerabilities per quarter of Debian LTS')
        plt.xlabel('Quarter')
        carlosplt.post_paper_plot(True,True,True)
        plt.show()
    
        ## Filter only wheezy:
        quarter_sum_regular = [0] * (12*4+1) + quarter_sum[12*4+1:12*4+9] + [0] * 12
        quarter_sum_errors = [0] * (12*4 + 9) + quarter_sum[12*4+9:12*4+9+5] + [0] * 7
        LTS_quarter = [0] * (15*4+2) + LTS_quarter[15*4+2:-3]
        
        whole_w = quarter_sum_regular[:-12] + quarter_sum_errors[12*4+9:-7] + LTS_quarter[15*4+2:]
    
        #print(quarter_sum_errors)
        cut = 12*4+1
        n = len(quarter_sum) - cut
        x = range(quarter_num-cut-3)
        width = 1/2
        
        #print(len(LTS_quarter))
        print(len(x))
        print(len(quarter_sum_regular[cut:]))
        print(len(quarter_sum_errors[cut:]))
        bar1 = plt.bar(x, quarter_sum_regular[cut:], width, color='darkblue', label='regular', edgecolor='black')
        bar12 = plt.bar(x, quarter_sum_errors[cut:], width, color='darkorange', label='regular*', edgecolor='black')
        bar2 = plt.bar(x, LTS_quarter[cut:], width, color='darkred', label ='long-term', edgecolor='black')
        plt.legend(handles=[bar1, bar12, bar2])
    
        plt.xticks(np.arange(0,n),quartersx[cut:], rotation="vertical")
        plt.ylabel('Vulnerabilities per quarter')
        plt.xlabel('Quarter')
        carlosplt.post_paper_plot(True,True,True)
        ## Linear Regression
        print(len(x))
        print(len(whole_w[cut:]))
        X = sm.add_constant(x)
        y = whole_w[cut:]
        model = sm.OLS(y,X).fit()
        predictions = model.predict(X)
        plt.plot(predictions)
        plt.show()
        print(model.summary())
        print(model.summary().as_latex())


def plot_all(src2month, src2sloccount, pkg_with_cvss):
    years = 18
    # 2001-2000+years

    myplotter = Plotter(src2month, src2sloccount, pkg_with_cvss, years)
    
    # consider severity (low, medium, high, undefined)
    # Undefined is usual for newly added packages
    myplotter.plot_all_severity(True,True,True,True)
    myplotter.plot_severity_percentage()
