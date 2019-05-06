
"""
All vendor models must extend this class.
"""

class VendorModel:
    def get_src2month(self):
        raise NotImplementedError

    def get_vendor_dir(self):
        raise NotImplementedError

    def unifySrcName(self, name):
        raise NotImplementedError

    def gen_model_opinion_set(self, filename, month, norm_param):
        raise NotImplementedError

    def performTests(self):
        raise NotImplementedError

    def load_latest_prediction_model(self):
        raise NotImplementedError
