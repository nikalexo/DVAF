import matplotlib.pyplot as plt
import json
import numpy as np
import paper_plots as carlosplt
import seaborn as sns
from matplotlib.font_manager import FontProperties

class TypePlotter:
    def __init__(self, data, years):
        self.src2dsa = data.src2dsa
        self.dsa2cve = data.dsa2cve
        self.cvetable = data.cvetable
        self.pkg_with_cvss = data.pkg_with_cvss
        self.src2cwe = data.src2cwe
        self.years = years
        self.src2monthDLA = dict()
        self.DLA_withcwe = dict()
        with open("src2month_DLA.json", "r") as fp:
            self.src2monthDLA = json.load(fp)
        with open("DLA_withcwe.json", "r") as fp:
            self.DLA_withcwe = json.load(fp)

    def plot_types(self):

        src2cwe_sum = []
        for i in range(0, 12*self.years):
            src2cwe_sum.append([0]*12)
        
        for pkg in self.src2cwe:
            for i in range(len(self.src2cwe[pkg])):
                for j in range(len(self.src2cwe[pkg][i])):
                    src2cwe_sum[i][j] += self.src2cwe[pkg][i][j]

        src2cwe_sumofsums = [0]*12

        for month in src2cwe_sum:
            for j in range(len(month)):
                src2cwe_sumofsums[j] += month[j]


        print(src2cwe_sumofsums)

        cwe2month = dict()
        for j in range(12):
            cwe2month[j] = []

        for month in src2cwe_sum:
            for j in range(len(month)):
                cwe2month[j].append(month[j])

        print(cwe2month[1])
        print(sum(cwe2month[1]))

        for i in range(12):
            binned = []
            for j in range(self.years*3):
                binned.append(sum(cwe2month[i][4*j:4*j+4]))
            #plt.plot(binned)
            #plt.show()

        percent = []
        for i in range(self.years):
            temp = [0]*12
            for j in range(12):
                temp[j] = sum(cwe2month[j][12*i:12*i+12])
            sum_temp = sum(temp)
            try:
                temp_percent = list(map(lambda x: x / sum_temp, temp))
                percent.append(temp_percent)
            except ZeroDivisionError:
                percent.append(temp)
                print('Year ', i+1, 'is the problem')

        print(percent)
        carlosplt.pre_paper_plot()
        x = range(2000,2000+self.years)
        y = []
        labels_cwe = ['682', '118', '664', '691', '693', '707', '710', 'N/A']
        for i in range(12):
            if i not in [2,3,7,8]:
                y.append([j[i] for j in percent[8:]])

        pal = sns.color_palette("Paired", 12)

        h = plt.stackplot(x[8:], y, colors = pal, alpha=0.9, labels = labels_cwe)
        plt.xticks(x[8:])
        fontP = FontProperties()
        fontP.set_size('small')
        plt.legend(loc='upper left', handles = h[::-1], prop=fontP)
        carlosplt.post_paper_plot(True,True,True)
        plt.show()

        self.plot_wheezyTypes(src2cwe_sum)
        return 0

    def plot_peryearstable(self):
        ## Plot the proportion changes over the years (All 11 types? - top 5 types).
        pass


    def plot_wheezyTypes(self, cwe_sum):
        ## Plot the changes in Wheezy for the top 3 types of vulnerabilities.
        ## Plot for wheezy
        quarter_num = 4 * self.years
        quarter_sum = dict()
        quarter_sum_DLA = dict()

        ## DSA Q2'13-Q2'16
        ## DLA Q3'16-Q2'18
        cwe_sum_DLA = []
        for i in range(0, 12*self.years):
            cwe_sum_DLA.append([0]*12)
        
        for pkg in self.DLA_withcwe:
            for i in range(len(self.DLA_withcwe[pkg])):
                for j in range(len(self.DLA_withcwe[pkg][i])):
                    for k in range(len(self.DLA_withcwe[pkg][i][j])):
                        cwe_sum_DLA[i*12+j][k] += self.DLA_withcwe[pkg][i][j][k]
        
        for cwe in range(len(cwe_sum[0])):
            print(cwe)
            quarter_sum[cwe] = [0] * quarter_num
            quarter_sum_DLA[cwe] = [0] * quarter_num
            for m in range(quarter_num):
                quarter_sum[cwe][m] = cwe_sum[3*m][cwe] + cwe_sum[3*m+1][cwe] + cwe_sum[3*m+2][cwe]
                quarter_sum_DLA[cwe][m] = cwe_sum_DLA[3*m][cwe] + cwe_sum_DLA[3*m+1][cwe] + cwe_sum_DLA[3*m+2][cwe]

        print(quarter_sum)
        print(quarter_sum_DLA)
        quartersx = []
        for i in range(1,self.years+1):
            for j in range(1,5):
                if j==1:
                    quartersx.append('Q' + str(j)+'\''+str(i).zfill(2))
                else:
                    quartersx.append(' ')

        ## Filter only wheezy. Do it for a selection of types:
        root_list = ['682', '118', '330', '435', '664', '691', '693', '697', '703', '707', '710' ]
        fig = plt.figure()
        
        ii = 0
        for j in [1, 4, 6, 11]:
            ii += 1
            quarter_sum_regular = [0] * (12*4+1) + quarter_sum[j][12*4+1:12*4+9] + [0] * 12
            quarter_sum_errors = [0] * (12*4 + 9) + quarter_sum[j][12*4+9:12*4+9+5] + [0] * 7
            LTS_quarter = [0] * (15*4+2) + quarter_sum_DLA[j][15*4+2:-3-4]
            
            #print(quarter_sum_errors)
            cut = 12*4+1
            n = len(quarter_sum[j]) - cut -7
            x = range(quarter_num-cut-3-4)
            width = 1/2
            
            #print(len(LTS_quarter))
            print(len(x))
            print(len(quarter_sum_regular[cut:]))
            print(len(quarter_sum_errors[cut:]))
            print(len(LTS_quarter[cut:]))
            
            ax = fig.add_subplot(2,2,ii)
            
            bar1 = plt.bar(x, quarter_sum_regular[cut:], width, color='darkblue', label='regular', edgecolor='black')
            bar12 = plt.bar(x, quarter_sum_errors[cut:], width, color='darkorange', label='regular*', edgecolor='black')
            bar2 = plt.bar(x, LTS_quarter[cut:], width, color='darkred', label ='long-term', edgecolor='black')
            if ii==2:
                plt.legend(handles=[bar1, bar12, bar2])
    
            plt.xticks(np.arange(0,n),quartersx[cut:], rotation="vertical")
            try:
                plt.ylabel('CWE-' + root_list[j])
            except IndexError:
                plt.ylabel('N/A')
            plt.xlabel('Quarter')
            carlosplt.post_paper_plot(True,True,True)
            
        plt.show()
