import subprocess
import glob
import paper_plots as carlosplt
import matplotlib.pyplot as plt
from scipy.stats import spearmanr

def download_data(src2month):
    create_folders(src2month)
    for pkg in src2month:
        print(pkg)
        bashCommand = "apt-get source --only-source " + pkg
        pwd = './source_files/'+pkg+'/'
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, cwd=pwd)
        output, error = process.communicate()
        #print(output, error)
    
    return 0

def create_folders(src2month):
    for pkg in src2month:
        bashCommand1 = "mkdir " + pkg
        process = subprocess.Popen(bashCommand1.split(), stdout=subprocess.PIPE, cwd='./source_files')
        output, error = process.communicate()

def test_pop(src2month, src2pop):
    ar1 = []
    ar2 = []
    for pkg in src2month:
        try:
            ar1.append(int(src2pop[pkg]))
        except KeyError:
            #print(pkg + ": no popularity data found!")
            continue
        total = sum(src2month[pkg])
        if total>100:
            print(pkg + ', ' + str(total) + ', ' + src2pop[pkg])
        ar2.append(total)

    vulns_sorted_pop=[x for _,x in sorted(zip(ar1,ar2), reverse=True)]
    pop_xaxis=[y for y,_ in sorted(zip(ar1,ar2), reverse=True)]

    half_more_popular = sum(vulns_sorted_pop[:int(len(vulns_sorted_pop)/2)])
    half_less_popular = sum(vulns_sorted_pop[int(len(vulns_sorted_pop)/2):])

    print(half_more_popular)
    print(half_less_popular)
    
    print(pop_xaxis[0])
    print(pop_xaxis[len(pop_xaxis)-1])

    print(src2pop)

    print(spearmanr(ar1,ar2))

    carlosplt.pre_paper_plot(True)


    plt.plot(vulns_sorted_pop)
    plt.ylabel('Number of vulnerabilities')
    plt.xlabel('Popularity ranking')
    carlosplt.post_paper_plot(True,True,True)

    plt.show()

def test_slocs(src2month, src2sloccount):
    # Remember sloccount is of the form (total, [ansic, cpp, asm, java, python, perl, sh])
    ar1 = []
    ar2 = []
    print(sum(src2month['linux']))
    for pkg in src2month:
        try:
            total_slocs = src2sloccount[pkg][0]
            if total_slocs == 0:
                continue
            else:
                ar1.append(int(total_slocs))
        except KeyError:
            print(pkg + ": no sloccount data found!")
            continue
        total = sum(src2month[pkg])
        if total>100:
            print(pkg + ', ' + str(total) + ', ' + str(total_slocs))
        ar2.append(total)
    
    vulns_sorted_slocs_total=[x for _,x in sorted(zip(ar1,ar2), reverse=True)]
    pop_xaxis=[y for y,_ in sorted(zip(ar1,ar2), reverse=True)]

    half_more_slocs = sum(vulns_sorted_slocs_total[:int(len(vulns_sorted_slocs_total)/2)])
    half_less_slocs = sum(vulns_sorted_slocs_total[int(len(vulns_sorted_slocs_total)/2):])

    print(half_more_slocs)
    print(half_less_slocs)

    print(pop_xaxis[0])
    print(pop_xaxis[len(pop_xaxis)-1])

    print(spearmanr(ar1,ar2))

    carlosplt.pre_paper_plot(True)


    plt.plot(vulns_sorted_slocs_total)
    plt.ylabel('Number of vulnerabilities')
    plt.xlabel('Number of SLOCS ranking')
    carlosplt.post_paper_plot(True,True,True)

    plt.show()

def download_old_data(src2month,year):
    create_old_folders(src2month,year)
    for pkg in src2month:
        print(pkg)
        bashCommand = "apt-get download " + pkg
        pwd = './Old_sources/' + str(year) + '/' + pkg+'/'
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, cwd=pwd)
        output, error = process.communicate()
        #print(output, error)
    
    return 0

def create_old_folders(src2month,year):
    for pkg in src2month:
        bashCommand1 = "mkdir " + pkg
        process = subprocess.Popen(bashCommand1.split(), stdout=subprocess.PIPE, cwd='./Old_sources/' + str(year) + '/')
        output, error = process.communicate()



def test(src2month, src2pop, src2sloccount):
    get_data= False
    year=2015
    get_old_data=False
    print(len(src2month))

    if(get_data):
        download_data(src2month)

    if(get_old_data):
        download_old_data(src2month,year)
    
    #test_slocs(src2month, src2sloccount)

    #p1, = plt.plot(src2month['apache2'], color = 'red', label='apache')
    #p2, = plt.plot(src2month['lighttpd'], color = 'blue', label='lighttpd')
    #p3, = plt.plot(src2month['nginx'], color = 'green', label='nginx')
    #plt.legend(handles=[p1, p2, p3])
    #plt.show()
    
    #p1, = plt.plot(src2month['openssl'], color = 'red', label='openssl')
    #p2, = plt.plot(src2month['gnutls28'], color = 'blue', label='gnutls')
    #plt.legend(handles=[p1, p2])
    #plt.show()

#    test_language(src2month)
#    test_pop(src2month, src2pop)
#    test_history(src2month)

    for pkg in ['linux', 'firefox-esr', 'chromium-browser', 'openjdk-8', 'icedove', 'php7.0', 'mysql-transitional', 'openssl', 'qemu']:
        total_previous=sum(src2month[pkg][-24-9-9:-24-9])
        total_validation=sum(src2month[pkg][-24-9:-24])
        dif=total_validation-total_previous

        print(pkg + ' previous: ' + str(total_previous))
        print(pkg + ' validation: ' + str(total_validation))
        print(pkg + ' dif: ' + str(dif))
        print('#'*80)

    return 0
