import csv
from CertainTrust import Opinion


class CSVReader:
    gathered_predictions = dict()

    @staticmethod
    def read_csv_prediction_errorcompl(inputfile, vendormodel, months, f=0.5, norm_param=4):
        '''
        Converts input csv file into a dictionary of opinions,
        The CSV input file should contain the following structure:
        packageName:prediction:errorComplement:initial_expectation
        :param inputfile: relative path to input csv file
        :param vendormodel: vendor model, needed for unifying the source-name of a package
        :param f: initial expectation value, will be used if csv does not contain row[3]
        :param months: number of months
        :return: dictionary of package-names as key and opinions as value
        '''
        result = {}
        with open(inputfile, newline="") as csvfile:
            reader = csv.reader(csvfile, delimiter=':')

            for row in reader:
                if not len(row) == 0:
                    package = vendormodel.unifySrcName(row [0])
                    prediction = float(row [1])
                    CSVReader.gathered_predictions[package]=prediction
                    errorCompl = float(row [2])
                    resT = 1 - prediction / (30 * months * norm_param)
                    if len(row)==4:
                        oldf = float(row[3])
                        newf = 1 + ( (oldf - 1) / (norm_param / 4 ))
                        result[package]=Opinion(resT, errorCompl, newf)
                    else:
                        result[package] = Opinion(resT, errorCompl, f)
        return result

    @staticmethod
    def read_csv_opinons(months):
        '''
        Reads a opinions from CSV file into python dictionary
        The CSV input file should contain the following structure:
        packageName:t:c:f
        :param months: number of months
        :return: dictionary of package-names as key and opinions as value
        '''
        result = {}
        with open("vendors/debian/models/dummy_model_"+str(months)+".csv", newline="") as csvfile:
            reader = csv.reader(csvfile, delimiter=':', quotechar='|')
            for row in reader:
                if not len(row) == 0:
                    result[row[0]]=Opinion(float(row[1]),float(row[2]),float(row[3]))
        return result

    @staticmethod
    def read_csv_package_names(filename):
        '''
        reads package names from csv file
        :param filename:
        :return: dictionary of package names
        '''
        result = []
        with open(filename, newline="") as csvfile:
            reader = csv.reader(csvfile, delimiter=':', quotechar='|')
            for row in reader:
                if not len(row) == 0:
                    result.append(row[0])
        return result


'''
res =CSVReader.readCSV("inputs/dummy_input.csv", 1, 3)
for key in res:
    print(key + ":" + str(res[key].t)+ ":" + str(res[key].c)+ ":" + str(res[key].f))

CSVReader.read_csv_package_names("inputs/dummy_input_package.csv")
'''
# /home/keks/mstar/mstar-project/vendors/debian/inputs/dummy_input_package_prediction_errorcompl.csv


