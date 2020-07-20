from load_data import load_DBs
from plot_functions import plot_all
from plot_types import TypePlotter
from laplace_tests import calc_laplace as claplace

class Mydata:
    def __init__(self, load):
        if load:
            (self.dsatable, self.src2dsa, self.dsa2cve, self.cvetable, self.src2month, self.src2sloccount, self.src2pop, self.src2deps, self.pkg_with_cvss, self.src2cwe) = load_DBs()
        else:
            print('no load command given')

def main():
    data = Mydata(True)
    print('Done')
    i = plot_all(data.src2month, data.src2sloccount, data.pkg_with_cvss)
    #
    years = 19
    # 2000-2018
    
    j = TypePlotter(data, years)
    j.plot_types()

    sum_linux = 0
    for num in data.src2month['linux'][:-12]:
        sum_linux += num
    print(sum_linux)

    #l = claplace(data,years)

if __name__ == "__main__":
    main()
