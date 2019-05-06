from pymongo import MongoClient
from vendors.debian.CVEParse import CVEParse as cparse
import json
from fixcwes import ret_roots
import matplotlib.pyplot as plt
import seaborn as sns
import paper_plots as carlosplt

cves = []
client = MongoClient()


with open('afl_data.txt', 'r') as f:
    for line in f:
        cves.append(line[:-1])

cwes = []

for cve_id in cves:
    cve = cparse.fetchCVE(cve_id, client)
    cvestats = cparse.parseCVE(cve_id, cve)
    cwes.append(cvestats[4])

cwes_counter = dict()

for cwe in cwes:
    if cwe in cwes_counter:
        cwes_counter[cwe] += 1
    else:
        cwes_counter[cwe] = 1

with open("cwe_afl.json","w") as fp:
        json.dump(cwes_counter,fp)

print(cwes_counter)
path = './vendors/debian/cache/cvetable'
cvetable = dict()

with open(path) as f:
    cvetable = json.load(f)

ii = 0

for cve_id in cves:
    if cve_id in cvetable:
        ii += 1

cwes_deb = []

for cve_id in cves:
    if cve_id in cvetable:
        cve = cparse.fetchCVE(cve_id, client)
        cvestats = cparse.parseCVE(cve_id, cve)
        cwes_deb.append(cvestats[4])

cwes_counter_deb = dict()

for cwe in cwes_deb:
    if cwe in cwes_counter_deb:
        cwes_counter_deb[cwe] += 1
    else:
        cwes_counter_deb[cwe] = 1

with open("cwe_afl_deb.json","w") as fp:
        json.dump(cwes_counter_deb,fp)

print(ii)
root_list = ['CWE-682', 'CWE-118', 'CWE-664', 'CWE-693', 'CWE-710', 'rest' ]
data = [29, 158, 23, 27, 39, 62]

carlosplt.pre_paper_plot()

fig1, ax1 = plt.subplots()

ax1.pie(data, labels=root_list, autopct='%1.1f%%', startangle=90)

#draw circle
centre_circle = plt.Circle((0,0),0.70,fc='white')
fig = plt.gcf()
fig.gca().add_artist(centre_circle)

# Equal aspect ratio ensures that pie is drawn as a circle
ax1.axis('equal')  
plt.tight_layout()
carlosplt.post_paper_plot(True,True,True)
plt.show()
