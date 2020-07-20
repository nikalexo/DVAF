import json
from datetime import datetime
from dateutil import parser
import matplotlib.pyplot as plt
import numpy as np
import paper_plots as carlosplt
from scipy.stats import shapiro
from scipy.stats import ks_2samp
import seaborn as sns
import statsmodels.api as sm
from statistics import median

def main():
    data = dict()
    with open("reports.json","r") as fp:
        data = json.load(fp)

    reports_id = dict()
    reports_team = dict()
    teams = []
    sum_team = dict()

    flag = True
    for chunk in data:
        for page_id in chunk:
            for report in chunk[page_id]:
                reports_id[report['id']] = report
                team = report['team']['handle']
                if team in reports_team:
                    reports_team[team].append(report)
                else:
                    teams.append(team)
                    reports_team[team] = []
                    reports_team[team].append(report)

    for team in reports_team:
        sum_team[team] = len(reports_team[team])

    with open("reports_team.json", "w") as fp:
        json.dump(reports_team, fp)
    with open("sum_team.json", "w") as fp:
        json.dump(sum_team, fp)

def plot_bounties(ff):
    reports_team = dict()
    sum_team = dict()
    with open("reports_team.json", "r") as fp:
        reports_team = json.load(fp)

    with open("sum_team.json", "r") as fp:
        sum_team = json.load(fp)

    if ff < 2:
        ibb_list = ['ibb-php', 'ibb-python', 'ibb-data', 'ibb-flash', 'ibb-nginx', 'ibb-perl', 'internet', 'ibb-openssl', 'ibb-apache']
        print('list follows')
        for j in ibb_list:
            print(reports_team[j])
    else:
        ibb_list = [team for team in reports_team]
    
    most_team = dict()
    sum_bounty_team = dict()
    for team in ibb_list:
        old = 0.0
        old_sum = 0.0
        for report in reports_team[team]:
            try:
                new = float(report['total_awarded_bounty_amount'])
                old_sum += new
            except KeyError:
                print('#'*80)
                print(report)
                print('Report id ', report['id'], ' - bounty not found')
                continue
            if new > old:
                old = new
        most_team[team] = old
        sum_bounty_team[team] = old_sum

    print(most_team)
    print(sum_bounty_team)

    month2sum = []
    month2money = []
    month2bountylist = []

    #Years: 2001-2018
    for i in range(12*18):
        month2sum.append(0)
        month2money.append(0.0)
        month2bountylist.append([])

    for team in ibb_list:
        for report in reports_team[team]:
            datetime_obj = parser.parse(report['latest_disclosable_activity_at'])
            print(str(datetime_obj))
            month2sum[(int(datetime_obj.year)-2001)*12 + datetime_obj.month] += 1
            try:
                #if report['severity_rating'] == "high":
                if (ff==0 or ff ==2) or (report['severity_rating'] == "high") or (report['severity_rating'] == "critical"):
                    month2money[(int(datetime_obj.year)-2001)*12 + datetime_obj.month] += float(report['total_awarded_bounty_amount'])
                    month2bountylist[(int(datetime_obj.year)-2001)*12 + datetime_obj.month] += [float(report['total_awarded_bounty_amount'])]
            except KeyError:
                continue

    print(month2bountylist)

    #plt.plot(month2sum[-12*5:])
    #plt.show()
    
    #plt.plot(month2money[-12*5:])
    #plt.show()

    years = 18
    quarter_num = years*4
    quarter_sum = []
    quarter_av = []
    carlosplt.pre_paper_plot()

    quarter2bountylist = []
    
    
    quartersx = []
    for i in range(1,years+1):
        for j in range(1,5):
            if j==1:
                quartersx.append('Q' + str(j)+'\''+str(i).zfill(2))
            else:
                quartersx.append(' ')
    
    for j in range(quarter_num):
        temp2 = sum(month2money[3*j:3*(j+1)])
        temp3 = [item for sublist in month2bountylist[3*j:3*(j+1)] for item in sublist]
        temp1 = len(temp3)
        print(temp3)
        quarter_sum.append(temp1)
        quarter2bountylist.append(temp3)
        try:
            quarter_av.append(temp2/temp1)
        except ZeroDivisionError:
            quarter_av.append(0)


    n = len(quarter_sum[-4*5:])
    x = range(len(quarter_sum[-4*5:]))
    width = 1/2

    #plt.bar(x[-4*5:], quarter_sum[-4*5:], width, color='brown', label='Number', edgecolor='black')
    
    #plt.xticks(np.arange(0,n),quartersx[-4*5:], rotation="vertical")
    #plt.ylabel('Number of rewards')
    #plt.xlabel('Quarter')
    #carlosplt.post_paper_plot(True,True,True)
    #plt.show()
    #
    #plt.bar(x[-4*5:], quarter_av[-4*5:], width, color='darkblue', label='regular support', edgecolor='black')
   # 
    #plt.xticks(np.arange(0,n),quartersx[-4*5:], rotation="vertical")
    #plt.ylabel('Average bug price of IBB projects (USD)')
    #plt.xlabel('Quarter')
    #carlosplt.post_paper_plot(True,True,True)
    #plt.show()

    #print(quarter2bountylist)
    if ff==0:
        labeltext = 'IBB-all'
    elif ff==1:
        labeltext = 'IBB-high'
    elif ff==2:
        labeltext = 'All-all'
    elif ff==3:
        labeltext = 'All-high'
    
    ## Shapiro normality test for each quarter
    ## Added powerlaw test
    reference = []
    for i in quarter2bountylist:
        reference+=i
    print(reference)

    for i in quarter2bountylist:
        print(i)
        data = i
        if len(i)>3:
            #sns.distplot(i)
            #plt.show()
            stat, p = shapiro(data)
            print('Statistics=%.3f, p=%.3f' % (stat, p))
            # interpret
            alpha = 0.01
            if p > alpha:
                print('Sample looks Gaussian (fail to reject H0)')
            else:
                print('Sample does not look Gaussian (reject H0)')

            w,p = ks_2samp(i,reference)
            if p > alpha:
                print('Samples look similar')
            else:
                print('Samples do not look similar')
            #mydata = i
            #results=powerlaw.Fit(mydata, discrete=False, xmax=5000)
            #print('alpha = ',results.power_law.alpha)
            #print(results.truncated_power_law.alpha)
            #print('xmin = ',results.power_law.xmin)
            #print('xmax = ',results.power_law.xmax)
            #print('sigma = ',results.power_law.sigma)
            #print('D = ',results.power_law.D)
            #print(results.truncated_power_law.xmin)
            #print('xmax = ', results.truncated_power_law.xmax)
            #print(results.power_law.discrete)
            #print('lognormal mu: ',results.lognormal.mu)
            #print('lognormal sigma: ',results.lognormal.sigma)

    ## Linear regression of average and median
    # Average
    xx = []
    yy = quarter_av[-4*5:]
    y = []
    counter=0
    for i in yy:
        if i!=0:
            y.append(i)
            xx.append(counter)
        counter+=1
    
    X = sm.add_constant(xx)
    model = sm.OLS(y,X).fit()
    predictions = model.predict(X)
    plt.plot(xx,predictions)
    print(model.summary())
    print(model.summary().as_latex())
    
    xx = []
    yy = quarter2bountylist[-4*5:]
    y = []
    counter=0
    for i in yy:
        if i!=[]:
            y.append(median(i))
            xx.append(counter)
        counter+=1
    
    X = sm.add_constant(xx)

    model = sm.OLS(y,X).fit()
    predictions = model.predict(X)
    plt.plot(xx,predictions, color='darkred')
    print(model.summary())
    print(model.summary().as_latex())

    ## Create box plot
    bp = plt.boxplot((quarter2bountylist[-4*5:]), whis = [5,95], patch_artist=True, positions = x)
    plt.setp(bp['boxes'], color='black')
    plt.setp(bp['whiskers'], color='darkred')
    plt.setp(bp['caps'], color='darkred')
    plt.setp(bp['fliers'], markersize = 3.0)
    plt.yscale('log')
    plt.ylim(top=50000)
    plt.ylim(bottom=1)
    plt.xticks(np.arange(0,n),quartersx[-4*5:], rotation="vertical")
    plt.ylabel(labeltext)
    plt.xlabel('Quarter')
    carlosplt.post_paper_plot(True,True,True)


def plot_demographics(ff):
    if ff==0:
        labeltext = 'num - IBB'
    elif ff==1:
        labeltext = 'new - IBB'
    elif ff==2:
        labeltext = 'num - All'
    elif ff==3:
        labeltext = 'new - All'
    reports_team = dict()
    sum_team = dict()
    with open("reports_team.json", "r") as fp:
        reports_team = json.load(fp)

    with open("sum_team.json", "r") as fp:
        sum_team = json.load(fp)

    if ff < 2:
        ibb_list = ['ibb-php', 'ibb-python', 'ibb-data', 'ibb-flash', 'ibb-nginx', 'ibb-perl', 'internet', 'ibb-openssl', 'ibb-apache']
        print('list follows')
        for j in ibb_list:
            print(reports_team[j])
    else:
        ibb_list = [team for team in reports_team]
    
    most_team = dict()
    sum_bounty_team = dict()
    for team in ibb_list:
        old = 0.0
        old_sum = 0.0
        for report in reports_team[team]:
            try:
                new = float(report['total_awarded_bounty_amount'])
                old_sum += new
            except KeyError:
                print('#'*80)
                print(report)
                print('Report id ', report['id'], ' - bounty not found')
                continue
            if new > old:
                old = new
        most_team[team] = old
        sum_bounty_team[team] = old_sum

    print(most_team)
    print(sum_bounty_team)

    month2sum = []
    month2money = []
    month2bountylist = []
    month2newreporters = []
    repuntilnow = []

    #Years: 2001-2018
    for i in range(12*18):
        month2sum.append(0)
        month2newreporters.append(0)
        month2money.append(0.0)
        month2bountylist.append([])

    for team in ibb_list:
        for report in reports_team[team]:
            datetime_obj = parser.parse(report['latest_disclosable_activity_at'])
            print(str(datetime_obj))
            month2sum[(int(datetime_obj.year)-2001)*12 + datetime_obj.month] += 1
            try:
                reporter=report['reporter']['id']
                #if report['severity_rating'] == "high":
                month2money[(int(datetime_obj.year)-2001)*12 + datetime_obj.month] += float(report['total_awarded_bounty_amount'])
                month2bountylist[(int(datetime_obj.year)-2001)*12 + datetime_obj.month] += [float(report['total_awarded_bounty_amount'])]
                if reporter not in repuntilnow:
                    month2newreporters[(int(datetime_obj.year)-2001)*12 + datetime_obj.month] += 1
                    repuntilnow.append(reporter)
            except KeyError:
                print('Error with report ', report['id'])
                continue

    print(month2bountylist)

    #plt.plot(month2sum[-12*5:])
    #plt.show()
    
    #plt.plot(month2money[-12*5:])
    #plt.show()

    years = 18
    quarter_num = years*4
    quarter_sum = []
    quarter_av = []
    carlosplt.pre_paper_plot()

    quarter2bountylist = []
    
    
    quartersx = []
    for i in range(1,years+1):
        for j in range(1,5):
            if j==1:
                quartersx.append('Q' + str(j)+'\''+str(i).zfill(2))
            else:
                quartersx.append(' ')
    
    for j in range(quarter_num):
        temp2 = sum(month2money[3*j:3*(j+1)])
        temp4 = sum(month2newreporters[3*j:3*(j+1)])
        temp3 = [item for sublist in month2bountylist[3*j:3*(j+1)] for item in sublist]
        temp1 = len(temp3)
        if ff==1 or ff==3:
            quarter_sum.append(temp4)
        else:
            quarter_sum.append(temp1)

    n = len(quarter_sum[-4*5:])
    x = range(len(quarter_sum[-4*5:]))
    width = 1/2
    #print(quarter2bountylist)

    
    reference = []
    for i in quarter2bountylist:
        reference+=i
    print(reference)

    ## Create bars plot
    plt.bar(x[-4*5:], quarter_sum[-4*5:], width, color='darkblue', label='Number', edgecolor='black')
    
    plt.xticks(np.arange(0,n),quartersx[-4*5:], rotation="vertical")
    plt.ylabel(labeltext)
    plt.xlabel('Quarter')
    carlosplt.post_paper_plot(True,True,True)


if __name__ == "__main__":
    #main()
    fig = plt.figure()
    carlosplt.pre_paper_plot()
    for i in range(4):
        ax = fig.add_subplot(2,2,i+1)
        plot_bounties(i)
        #plot_demographics(i)

    #plot_bounties(1)
    plt.show()
