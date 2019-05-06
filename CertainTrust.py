import numpy as np


class Opinion:
    """
    This class represents opinion.
    t - average rating
    c - certainty
    f - initial expectation value
    doc - degree of conflict
    """

    def __init__(self, t=0, c=0, f=1, doc=0):
        self.t = t
        self.c = c
        self.f = f
        self.doc = 0

    def __str__(self):
        return "Opinion{t: "+str(self.t)+", c: "+str(self.c)+", f: "+str(self.f)+"}"

    def expectation_value(self):
        return self.c * self.t + ( 1 - self.c ) * self.f

    @staticmethod
    def _single_or(o_A, o_B):
        """
        Computes OR function of two Opinion objects. Result is returned as a new object,
        arguments remain unchanged.
        N values of both objects should be equal.
        For detailed information see TODO
        :param o_A: opinion
        :param o_B: opinion
        :return: opinion as described above
        """
        r_f = o_A.f + o_B.f - o_A.f * o_B.f

        # FIXME: js implementation of this comparison is different from paper, using paper variant now
        if np.isclose(r_f, 0):
            # c1 + c2 - c1*c2
            r_c = o_A.c + o_B.c - o_A.c * o_B.c
        else:
            # restC = restC - (c1*f2*(1-c2)*(1-t1)+c2*f1*(1-c1)*(1-t2)) / resF
            r_c = o_A.c + o_B.c - o_A.c * o_B.c - (o_A.c * o_B.f * (1 - o_B.c) * (1 - o_A.t) + o_B.c * o_A.f * (1 - o_A.c) * (1 - o_B.t)) / r_f

        if np.isclose(r_c, 0):
            r_t = 0.5
        else:
            # resT = (1/resC) * (c1*t1 + c2*t2 - c1*c2*t1*t2);
            r_t = (1 / r_c) * (o_A.c * o_A.t + o_B.c * o_B.t - (o_A.c * o_B.c * o_A.t * o_B.t))

        r_t = Opinion._adjust_value(r_t)
        r_c = Opinion._adjust_value(r_c)
        r_f = Opinion._adjust_value(r_f)
        return Opinion(r_t, r_c, r_f)

    @staticmethod
    def _single_and(o_A, o_B):
        """
        Computes AND function of two Opinion objects. Result is returned as a new object,
        arguments remain unchanged.
        N values of both objects should be equal.
        For detailed information see TODO
        :param o_A: opinion
        :param o_B: opinion
        :return: opinion as described above
        """
        t1 = o_A.t
        c1 = o_A.c
        f1 = o_A.f
        t2 = o_B.t
        c2 = o_B.c
        f2 = o_B.f

        if np.isclose(f1*f2, 1):
            f1 = 0.999
            f2 = 0.999
        r_f = f1*f2




        if not np.isclose(r_f, 1):
            r_c = c1 + c2 - c1*c2 - (c2*t2*(1-c1)*(1-f1)+(c1*t1*(1-c2)*(1-f2))) / (1 - r_f);
        else:
            r_c = c1 + c2 - c1 * c2

        #FIXME: js implementation of this comparison is different from paper, using js variant now
        if np.isclose(r_c, 0):
            r_t = 0.5
        else:
            r_t = (1/r_c) *  ((c1*t1*c2*t2) + (c1*f2*t1*(1-c2)*(1-f1)+c2*f1*t2*(1-c1)*(1-f2)) / (1 - r_f));

        r_t = Opinion._adjust_value(r_t)
        r_c = Opinion._adjust_value(r_c)
        r_f = Opinion._adjust_value(r_f)
        return Opinion(r_t, r_c, r_f)

    @staticmethod
    def _not(o):
        """
        Computes NOT function of an Opinion object. Result is returned as a new object,
        argument remains unchanged.
        :param o: Opinion
        :return: opinion as described above
        """
        r_t=o.t
        r_c=o.c
        r_f=1-o.f
        r_doc=0
        return Opinion(r_t, r_c, r_f, r_doc)

    @staticmethod
    def _cum_or(opar):
        """
        For a list of opinions, compute a cummulated OR opinion.
        :param opar:list of opinions
        :return: OR-cummulated opinion
        """
        res = opar[0]
        for o in opar[1:]:
            res = Opinion._single_or(res, o)
        return res

    @staticmethod
    def _cum_and(opar):
        """
        For a list of opinions, compute a cummulated AND opinion.
        :param opar: list of opinions
        :return: AND-cummulated opinion
        """
        res = opar[0]
        for o in opar[1:]:
            res = Opinion._single_and(res, o)
        return res

    @staticmethod
    def _internal_fusion(args, weights, doc=1.0):
        """
        An internal implementation of fusion function.
        Is called by _weighted_fusion and cFusion.
        :param args: list of opinions
        :param weights: list of weights
        :param doc: degree of conflict (float)
        :return:
        """
        allOne = True;
        allZero = True;
        allWeightsZero = True;
        atLeastOne1 = False;
        arrLength = len(args);

        for o in args:
            if o.c != 1:
                allOne = False
            if o.c != 0:
                allZero = False
            if o.c == 1:
                atLeastOne1 = True

        for w in weights:
            if w != 0:
                allWeightsZero = False
                break

        numeratorT = 0
        denominatorT = 0

        if allOne:
            r_c = 1 * (1 - doc)

            if(allWeightsZero):
                r_t = 0
            else:
                for i in range(0,arrLength):
                    numeratorT += weights[i] * args[i].t
                    denominatorT += weights[i]
        else:
            if atLeastOne1:
                raise Exception("Illegal arguments. Either all C values must equal 1 or none of them. Operation not allowed!")
            else:
                if allWeightsZero:
                    r_t = 0
                    r_c = 0
                else:
                    denominatorC = 0
                    numeratorC = 0
                    for i in range(0, arrLength):
                        mult = 1
                        for j in range(0, arrLength):
                            if j != i:
                                mult *= 1 - args[j].c
                        numeratorT = numeratorT + weights[i] * args[i].t * args[i].c * mult
                        denominatorT = denominatorT + weights[i] * args[i].c * mult
                        denominatorC = denominatorC + weights[i] * mult

                    numeratorC = denominatorT
                    r_c = (numeratorC / denominatorC) * (1 - doc)
                    if allZero:
                        r_t = 0.5
                    else:
                        r_t = numeratorT / denominatorT
                if allZero:
                    r_t = 0.5;
        if allWeightsZero:
            r_f = 0;
        else:
            numerator = 0
            denominator = 0
            for i in range(0, arrLength):
                numerator = numerator + weights[i] * args[i].f
                denominator = denominator + weights[i]
            r_f = numerator / denominator

        return Opinion(r_t, r_c, r_f, doc);

    @staticmethod
    def _weighted_fusion(args, weights):
        """
        Performs weighted fusion for an array of Opinions objects in correspondence with
        an array of weights. Returns new Opinion object.
        Requirements: N values of Opinion objects must be equal.
        Number of weights should equal the number of Opinion objects.
        Arrays must be non-empty
        Either all of CertainTrust must be of certainty 1 or none of them.
        :param args: an array of Opinions
        :param weights: an integer array of corresponding weights
        :return: new Opinion
        """
        if len(args) == len(weights) and len(args) != 0:
            return Opinion._internal_fusion(args, weights, 0)
        else:
            raise Exception("_weighted_fusion is not allowed for these arguments")

    @staticmethod
    def _conflicted_fusion(args, weights):
        """
        Conflicted Fusion is a variation of weighted fusion, which additionally computes the degree of conflict
        between given Opinions and takes it into consideration while performing fusion.
        The degree of conflict is then saved in the resulting Opinion object.
        :param args:
        :param weights:
        :return:
        """
        if len(args) == len(weights) and len(args) != 0:
            denominator = len(args)*(len(args) - 1) / 2
            numerator = 0
            for i in range(0,len(args)):
                for j in range(i,len(args)):
                    numerator = numerator + abs(args[i].t - args[j].t) * args[i].c * args[j].c * (1 - abs((weights[i] - weights[j]) / (weights[i] + weights[j])))
            doc = numerator/denominator
            return Opinion._internal_fusion(args, weights, doc)
        else:
            raise Exception("_conflicted_fusion is not allowed for these arguments")

    @staticmethod
    def _adjust_value(val):
        return max(min(val, 1), 0)

""" 
// TESTS
os = [Opinion(0.7,0.9,0.9), Opinion(0.4,0.7,1),Opinion(0.7,0.7,1),Opinion(0.2,0.9,1),Opinion(0.55,0.8,1)]
w = [1, 0.3, 0.2, 1, 0.5]
print(Opinion._single_or(os[0],os[1]))

print(Opinion._single_and(os[0],os[1]))

print(Opinion._cum_or(os))

print(Opinion._cum_and(os))

print(Opinion._internal_fusion(os, w, 1))

print(Opinion._conflicted_fusion(os, w))
"""
