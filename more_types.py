from load_data import load_DBs
from plot_functions import plot_all
from plot_types import TypePlotter
import json

class Mydata:
    def __init__(self, load):
        if load:
            (self.dsatable, self.src2dsa, self.dsa2cve, self.cvetable, self.src2month, self.src2sloccount, self.src2pop, self.src2deps, self.pkg_with_cvss, self.src2cwe) = load_DBs()
        else:
            print('no load command given')

def main():
    data = Mydata(True)
    cwe_counts = dict()
    for cvenum in data.cvetable:
        cwe = data.cvetable[cvenum][5]
        if cwe not in cwe_counts:
            cwe_counts[cwe] = 1
        else:
            cwe_counts[cwe] += 1
    with open('cwecounts.json', 'w') as outfile:
        json.dump(cwe_counts, outfile)



if __name__ == "__main__":
    main()
