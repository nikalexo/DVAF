import os
import random
import math

from CertainTrust import Opinion
from vendors.debian.CSVReader import CSVReader

class Tests:
    @staticmethod
    def system_input_prediction_error_test(model):
        """
        Compare errors of three predictions: cummulatedAnd , cummulated separate prediction, prediction from csv file
        :param model: model to perform tests
        :return: nope
        """
        norm_param = 4
        months = 9

        model_filename = os.path.join(model.module_path, "models", "dummy_input_package_prediction_errorcompl.csv")
        model_set = model.gen_model_opinion_set(model_filename, 9, norm_param)

        system_filename = os.path.join(model.module_path, "inputs", "dummy_input_package_server.csv")
        system = CSVReader.read_csv_package_names(system_filename)

        # get system dict
        system_dict = dict()
        for key in system:
            new_key = model.unifySrcName(key)
            if new_key in model_set:
                system_dict[new_key] = model_set[new_key]

        print("Evaluating on: " + str(len(system_dict)) + " out of " + str(
            len(system)) + " packages, since they are not present in our model.")

        and_prediction = Tests.acc_AND_prediction(system_dict, months, norm_param)
        sep_prediction = Tests.separate_prediction(system_dict, months, norm_param)
        csv_prediction = Tests.read_model_prediction(system_dict)
        s2m_prediction = Tests.get_src2month_data(system_dict, model, months)


        and_error = abs(and_prediction - s2m_prediction) / s2m_prediction
        sep_error = abs(sep_prediction - s2m_prediction) / s2m_prediction
        csv_error = abs(csv_prediction - s2m_prediction) / s2m_prediction

        print("and_error = "+str(and_error))
        print("sep_error = " + str(sep_error))
        print("csv_error = " + str(csv_error))

        return


    @staticmethod
    def random_input_prediction_error_test(model):
        """
        Compare errors of three predictions: cummulatedAnd , cummulated separate prediction, prediction from model
        :param model: model to perform tests
        :return: nope
        """

        norm_param = 4
        months = 9

        model_filename = os.path.join(model.module_path, "models", "dummy_input_package_prediction_errorcompl.csv")
        model_set = model.gen_model_opinion_set(model_filename, 9, norm_param)

        errors_dict=dict()
        errors_dict["and"]=[]
        errors_dict["sep"]=[]
        errors_dict["csv"]=[]

        # compute errors for 20 subsets
        for i in range(0, 100):
            # to compute the errors, wen need a random package_list dict of size 100
            subset = dict()
            while len(subset)!=100:
                package = random.choice(list(model_set))
                subset[package] = model_set[package]

            and_prediction = Tests.acc_AND_prediction(subset, months, norm_param)
            sep_prediction = Tests.separate_prediction(subset, months, norm_param)
            csv_prediction = Tests.read_model_prediction(subset)
            s2m_prediction = Tests.get_src2month_data(subset, model, months)

            errors_dict["and"].append(abs(and_prediction - s2m_prediction) / s2m_prediction)
            errors_dict["sep"].append(abs(sep_prediction - s2m_prediction) / s2m_prediction)
            errors_dict["csv"].append(abs(csv_prediction - s2m_prediction) / s2m_prediction)


        # given error dicts , we can compute the mean errors
        avg_and_error_normal = sum(errors_dict["and"])/len(errors_dict["and"])
        avg_sep_error_normal = sum(errors_dict["sep"]) / len(errors_dict["sep"])
        avg_csv_error_normal = sum(errors_dict["csv"]) / len(errors_dict["csv"])
        print("Normal errors: " + str(avg_and_error_normal) + " : " + str(avg_sep_error_normal) + " : " + str(avg_csv_error_normal))

        # quadratic errors
        avg_and_error_quadr = math.sqrt(sum(math.pow(i, 2) for i in errors_dict["and"]) / len(errors_dict["and"]))
        avg_sep_error_quadr = math.sqrt(sum(math.pow(i, 2) for i in errors_dict["sep"]) / len(errors_dict["sep"]))
        avg_csv_error_quadr = math.sqrt(sum(math.pow(i, 2) for i in errors_dict["csv"]) / len(errors_dict["csv"]))
        print("Quadratic errors: " + str(avg_and_error_quadr) + " : " + str(avg_sep_error_quadr) + " : " + str(avg_csv_error_quadr))


    @staticmethod
    def relativity_of_expectations_test(model):
        """
        Compares the relativeness of predictions of two sets, to relativeness of real data
        :param model:
        :return:
        """
        norm_param = 4
        months = 9

        model_filename = os.path.join(model.module_path, "models", "dummy_input_package_prediction_errorcompl.csv")
        model_set = model.gen_model_opinion_set(model_filename, 9, norm_param)

        computetd_rel_list = []
        real_rel_list = []

        for i in range(0, 100):
            # get two subsets
            subset1 = dict()
            while len(subset1)!=100:
                package = random.choice(list(model_set))
                subset1[package] = model_set[package]
            subset2 = dict()
            while len(subset2)!=100:
                package = random.choice(list(model_set))
                subset2[package] = model_set[package]

            # for these two sets, compute relativity of their ANDed predictions and of real data
            computed_rel_prediction = Tests.acc_AND_prediction(subset1, months, norm_param)/Tests.acc_AND_prediction(subset2, months, norm_param)
            computetd_rel_list.append(computed_rel_prediction)

            real_rel_prediction = Tests.get_src2month_data(subset1, model, months) / Tests.get_src2month_data(subset2, model, months)
            real_rel_list.append(real_rel_prediction)
            print("Computed relativity : " + str ( computed_rel_prediction ) + " : "+ str(real_rel_prediction))

        # at this point we have two lists of computed relatives, lets see how similair are they
        similarities = []
        for i in range(0, 100):
            similarity = abs(real_rel_list[i]-computetd_rel_list[i])
            similarities.append(similarity)

        print(similarities)
        avg_normal_relativity = sum(similarities)/len(similarities)
        avg_quadratic_relativity = math.sqrt(sum(math.pow(i, 2) for i in similarities) / len(similarities))
        print("Average normal relativity: " + str(avg_normal_relativity))
        print("Average quadratic relativity: "+str(avg_quadratic_relativity))


    ## helper methods
    @staticmethod
    def acc_AND_prediction(package_list, months, norm_val):
        """
        Returns accumulated and prediction for a list of packages
        :param package_list: dictionary with package_names as keys , opinions as values
        :param months: months
        :param norm_val: normalization value
        :return: prediction
        """
        system_and = Opinion._cum_and(list(package_list.values()))
        expectation = system_and.expectation_value()
        AND_prediction = (1 - expectation) * (norm_val * months * 30)
        return AND_prediction
        #and_error = abs(summ - AND_prediction) / summ
        #print("ANDed prediction = " + str(AND_prediction) + ", ( error = " + str(and_error) + " )")

    @staticmethod
    def separate_prediction(package_list, months, norm_val):
        """
        Returns summ of separated predictions for a list of packages
        :param package_list: dictionary with package_names as keys , opinions as values
        :param months: months
        :param norm_val: normalization value
        :return: prediction
        """
        sep_pred = 0
        for k in package_list:
            sep_pred = sep_pred + ((1 - package_list[k].expectation_value()) * (norm_val * months * 30))
        return sep_pred

    @staticmethod
    def read_model_prediction(package_list):
        """
        :param package_list: dictionary with package_names as keys , opinions as values
        :return: Summ of model-predictions
        """
        summ = 0
        for k in package_list:
            summ = summ + CSVReader.gathered_predictions[k]
        return summ

    @staticmethod
    def get_src2month_data(package_list, vendormodel, months):
        summ = 0
        for package in package_list:
            unified_package = vendormodel.unifySrcName(package)
            src2month = vendormodel.get_src2month()
            if unified_package in src2month:
                summ = summ + sum(src2month[package][-months - 3:-3])
        return summ