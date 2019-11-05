#!/usr/bin/env python
# coding: utf-8

# In[16]:


import json
from datetime import datetime
from dateutil import parser
import matplotlib.pyplot as plt
import numpy as np
import paper_plots as carlosplt
import operator
from dateutil import parser
import seaborn as sns
from matplotlib.font_manager import FontProperties


# In[2]:


with open("reports_team.json", "r") as fp:
    reports_team = json.load(fp)

with open("sum_team.json", "r") as fp:
    sum_team = json.load(fp)

ibb_list = ['ibb-php', 'ibb-python', 'ibb-data', 'ibb-flash', 'ibb-nginx', 'ibb-perl', 'internet', 'ibb-openssl', 'ibb-apache']


# In[3]:


print(len(reports_team['ibb-data']))
num_ibb=0
num_all_ibb=0
sum_ibb=0
max_ibb=0
av_ibb=0
for pkg in ibb_list:
    sumb=0
    numb=0
    maxb=0
    num_all=0
    for report in reports_team[pkg]:
        num_all+=1
        try:
            bounty = float(report['total_awarded_bounty_amount'])
            sumb+=bounty
            if bounty>maxb:
                maxb=bounty
            numb+=1
        except:
            continue
    print('#'*80,'\nComponent: ', pkg, '\nTotal bounty number: ', num_all, '\nDisclosed Num :', numb,'\nBounty Number with payment public: ', numb, '\nBounty Sum: ', sumb, '\nMax Bounty: ', maxb, '\nAverage Bounty: ', sumb/numb,'\n')
    num_ibb+=numb
    num_all_ibb+=num_all
    sum_ibb+=sumb
    if maxb>max_ibb:
        max_ibb=maxb
print(num_all_ibb, sum_ibb, max_ibb, sum_ibb/num_ibb, num_ibb)


# In[4]:


reporters=dict()
reporters_sum=dict()
for team in ibb_list:
    for report in reports_team[team]:

        try:
            if report['reporter']['id'] in reporters:
                reporters_sum[report['reporter']['id']]+=float(report['total_awarded_bounty_amount'])
                reporters[report['reporter']['id']]+=1
            else:
                reporters_sum[report['reporter']['id']]=float(report['total_awarded_bounty_amount'])
                reporters[report['reporter']['id']]=1
        except Exception as e:
            pass


# In[5]:


dictlist=[]
for key, value in reporters_sum.items():
    temp = float(value)
    dictlist.append(temp)

print(dictlist)
print(dictlist.sort(reverse=True))
print(dictlist)
plt.plot(dictlist)
plt.show()

# In[6]:


dictlist=[]
for key, value in reporters.items():
    temp = float(value)
    dictlist.append(temp)

print(dictlist)
print(dictlist.sort(reverse=True))
print(dictlist)
plt.plot(dictlist)
plt.show()

# In[7]:


sumall=0
numall=0
for team in reports_team:
    for report in reports_team[team]:
        try:
            sumall+=float(report['total_awarded_bounty_amount'])
        except:
            continue
print(sumall)


# In[8]:


print(len(reporters))
print(len(reporters_sum))
sorted_x = sorted(reporters_sum.items(), key=operator.itemgetter(1), reverse=True)
print(sorted_x[:10])
top_IBB=[]
for i in sorted_x[:50]:
    top_IBB.append(i[0])
print(top_IBB)


# In[ ]:





# In[9]:


years=5 #2014-2018
ibb_rep2month = 12*years*[0]
rest_rep2month = 12*years*[0]
ibb_bounty2month = 12*years*[0]
rest_bounty2month = 12*years*[0]

for team in reports_team:
    for report in reports_team[team]:
        try:
            date = parser.parse(report['latest_disclosable_activity_at'])
            if report['reporter']['id'] in reporters:
                if team in ibb_list:
                    ibb_bounty2month[(date.year-2014)*12+date.month]+=float(report['total_awarded_bounty_amount'])
                    ibb_rep2month[(date.year-2014)*12+date.month]+=1
                else:
                    rest_bounty2month[(date.year-2014)*12+date.month]+=float(report['total_awarded_bounty_amount'])
                    rest_rep2month[(date.year-2014)*12+date.month]+=1
        except Exception as e:
            pass


# In[10]:


print(ibb_rep2month)


# In[19]:


carlosplt.pre_paper_plot(True)
quartersx = []
for i in range(14,14+years):
    for j in range(1,5):
        if j==1:
            quartersx.append('Q' + str(j)+'\''+str(i).zfill(2))
        else:
            quartersx.append(' ')

ibb_rep2quart = []
rest_rep2quart = []
ibb_bounty2quart = []
rest_bounty2quart = []

quarter_num= len(quartersx)            
for j in range(quarter_num):
    temp1=sum(ibb_rep2month[3*j:3*(j+1)])
    temp2=sum(ibb_bounty2month[3*j:3*(j+1)])
    temp3=sum(rest_rep2month[3*j:3*(j+1)])
    temp4=sum(rest_bounty2month[3*j:3*(j+1)])
    
    try:
        temp_rep_ibb=temp1/(temp1+temp3)
        temp_rep_rest=temp3/(temp1+temp3)
    except ZeroDivisionError:
        temp_rep_ibb=0
        temp_rep_rest=0
    try:
        temp_bounty_ibb=temp2/(temp2+temp4)
        temp_bounty_rest=temp4/(temp4+temp2)
    except ZeroDivisionError:
        temp_bounty_ibb=0
        temp_bounty_rest=0
    
    ibb_rep2quart.append(temp_rep_ibb)
    ibb_bounty2quart.append(temp_bounty_ibb)
    rest_rep2quart.append(temp_rep_rest)
    rest_bounty2quart.append(temp_bounty_rest)
    
n = len(ibb_rep2quart)
x = range(len(ibb_rep2quart))
width = 1/2
pal = sns.color_palette("Paired", 12)
fig = plt.figure()

ax = fig.add_subplot(1,2,1)            
## Create bars plot
h = plt.stackplot(x, [ibb_bounty2quart, rest_bounty2quart], colors=pal, alpha=0.9)
plt.xticks(np.arange(0,n),quartersx, rotation="vertical")
labeltext='Amount ratio'
fontP = FontProperties()
fontP.set_size('small')

plt.ylabel(labeltext)
plt.xlabel('Quarter')
#plt.tight_layout()
carlosplt.post_paper_plot(True,True,True)
#plt.show()


# In[20]:


ax = fig.add_subplot(1,2,2)            
## Create bars plot
h = plt.stackplot(x, [ibb_rep2quart, rest_rep2quart], colors=pal, alpha=0.9, labels = ['in IBB','rest'])
plt.xticks(np.arange(0,n),quartersx, rotation="vertical")
labeltext='Reports ratio'
plt.ylabel(labeltext)
plt.xlabel('Quarter')
fontP = FontProperties()
fontP.set_size('small')
plt.legend(loc='upper right', handles = h[::-1], prop=fontP)
#plt.tight_layout()
plt.show()
carlosplt.post_paper_plot(True,True,True)

carlosplt.pre_paper_plot(True)
quartersx = []
for i in range(14,14+years):
    for j in range(1,5):
        if j==1:
            quartersx.append('Q' + str(j)+'\''+str(i).zfill(2))
        else:
            quartersx.append(' ')

ibb_rep2quart = []
rest_rep2quart = []
ibb_bounty2quart = []
rest_bounty2quart = []

quarter_num= len(quartersx)            
for j in range(quarter_num):
    temp1=sum(ibb_rep2month[3*j:3*(j+1)])
    temp2=sum(ibb_bounty2month[3*j:3*(j+1)])
    temp3=sum(rest_rep2month[3*j:3*(j+1)])
    temp4=sum(rest_bounty2month[3*j:3*(j+1)])
    
    try:
        temp_rep_ibb=temp1
        temp_rep_rest=temp3
    except ZeroDivisionError:
        temp_rep_ibb=0
        temp_rep_rest=0
    try:
        temp_bounty_ibb=temp2/1000
        temp_bounty_rest=temp4/1000
    except ZeroDivisionError:
        temp_bounty_ibb=0
        temp_bounty_rest=0
    
    ibb_rep2quart.append(temp_rep_ibb)
    ibb_bounty2quart.append(temp_bounty_ibb)
    rest_rep2quart.append(temp_rep_rest)
    rest_bounty2quart.append(temp_bounty_rest)
    
n = len(ibb_rep2quart)
x = range(len(ibb_rep2quart))
width = 1/2
pal = sns.color_palette("Paired", 12)
fig = plt.figure()

ax = fig.add_subplot(1,2,1)            
## Create bars plot
h = plt.stackplot(x, [ibb_bounty2quart, rest_bounty2quart], colors=pal, alpha=0.9)
plt.xticks(np.arange(0,n),quartersx, rotation="vertical")
labeltext='Bounty amount (k)'
fontP = FontProperties()
fontP.set_size('small')

plt.ylabel(labeltext)
plt.xlabel('Quarter')
#plt.tight_layout()
carlosplt.post_paper_plot(True,True,True)
#plt.show()


# In[20]:


ax = fig.add_subplot(1,2,2)            
## Create bars plot
h = plt.stackplot(x, [ibb_rep2quart, rest_rep2quart], colors=pal, alpha=0.9, labels = ['in IBB','rest'])
plt.xticks(np.arange(0,n),quartersx, rotation="vertical")
labeltext='Report number'
plt.ylabel(labeltext)
plt.xlabel('Quarter')
fontP = FontProperties()
fontP.set_size('small')
plt.legend(loc='upper left', handles = h[::-1], prop=fontP)
#plt.tight_layout()
carlosplt.post_paper_plot(True,True,True)
plt.show()
