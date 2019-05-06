import math
import sys

def laplace_test(ttr, tend):
    r = len(ttr)
    s = 0
    for ti in ttr:
        s += ti - (tend/2)
    try:
        z = (math.sqrt(12*r)*s)/(r*tend)
    except ZeroDivisionError:
        return(0)
    return(z)

def main():
    time_end = float(sys.argv[1])
    time_list = [float(i) for i in sys.argv[2:]]
    print(laplace_test(time_list, time_end))
    return


if __name__ == "__main__":
    main()
