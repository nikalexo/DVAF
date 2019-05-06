import csv
import re
import json

def find_roots(cwes_parents, root_list):

    roots = dict()

    for cwe in cwes_parents:
        ancestor_list = cwes_parents[cwe]
        roots[cwe] = recursive_ancestor(cwes_parents, ancestor_list, root_list)

    return(roots)

def recursive_ancestor(cwes_parents,ancestor_list, root_list):
    new_ancestor_list=[]
    for ancestor in ancestor_list:
        try:
            print(ancestor)
            new_ancestor_list += cwes_parents[ancestor]
        except KeyError:
            print('We have a problem with the following ancestor:')
            print(ancestor)
            print('#'*80)


    flag = True
    for i in new_ancestor_list:
        if i not in root_list:
            flag = False
            break
    
    if flag:
        return(new_ancestor_list)
    else:
        # Yes it is tail-recursive
        return(recursive_ancestor(cwes_parents,new_ancestor_list, root_list))

def ret_roots(cwe):
    roots = dict()
    with open("cwe_roots.json",'r') as fp:
        roots = json.load(fp)

    try:
        return(roots[cwe.split('-')[1]])
    except KeyError:
        return([0])
    except IndexError:
        return([0])
    except AttributeError:
        return([0])


def main():
    cwes_parents = dict()
    cwes_roots = dict()
    with open("1000.csv","r") as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',', quotechar='"')
        for row in spamreader:
            s = row[6]
            if row[0]=='732':
                print(s)
            m = re.findall(r'::NATURE:ChildOf:CWE ID:([0-9]*):VIEW ID:1000',s)
            try:
                #print(row[0],', ', row[6])
                #print(m.group(1))
                cwes_parents[row[0]] = m
                print(m)
            except AttributeError:
                print(s)
    root_list = ['682', '118', '330', '435', '664', '691', '693', '697', '703', '707', '710' ]

    for cwe in root_list:
        cwes_parents[cwe] = [cwe]

    cwe_roots = find_roots(cwes_parents, root_list)
    print(cwe_roots)
    with open("cwe_roots.json","w") as fp:
        json.dump(cwe_roots,fp)

if __name__ == "__main__":
    main()
