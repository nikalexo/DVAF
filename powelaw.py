import powerlaw
from numpy import genfromtxt
import matplotlib.pyplot as plt
import paper_plots as carlosplt


mydata = genfromtxt('power_law.csv', delimiter=',', dtype = 'float')
print(len(mydata))
print(mydata)

## Build and print probability distribution, bins per 10
distr = dict()
for i in mydata:
    bins = i // 10
    if bins in distr:
        distr[bins] += 1
    else:
        distr[bins] = 1

#for i in distr:
#    print(str(i) + ', ' + str(distr[i]))


results=powerlaw.Fit(mydata, discrete=False, estimate_discrete=False)
print('alpha = ',results.power_law.alpha)
print(results.truncated_power_law.alpha)
print('xmin = ',results.power_law.xmin)
print('xmax = ',results.power_law.xmax)
print('sigma = ',results.power_law.sigma)
print('D = ',results.power_law.D)
print(results.truncated_power_law.xmin)
print('xmax = ', results.truncated_power_law.xmax)
print(results.power_law.discrete)
print('lognormal mu: ',results.lognormal.mu)
print('lognormal sigma: ',results.lognormal.sigma)

#custom_model=[]
#for i in sorted(mydata,reverse=True):
#    ccdf =

#fig=results.plot_pdf(color='b', linewidth=2)
carlosplt.pre_paper_plot(True)
fig = results.plot_ccdf(color = 'darkblue', linestyle='-', label='data')
results.power_law.plot_ccdf(color = 'darkgreen', ax=fig, label='power-law fit')
#results.truncated_power_law.plot_ccdf(color = 'red', ax=fig)
#results.lognormal_positive.plot_ccdf(color = 'yellow', ax=fig)
#results.lognormal.plot_ccdf(color = 'brown', ax=fig)
#results.exponential.plot_ccdf(color = 'orange', ax=fig)
plt.ylabel('ccdf')
plt.xlabel('Vulnerabilities')
fig.legend()
carlosplt.post_paper_plot(True,True,True)
plt.show()
R, p=results.distribution_compare('power_law','exponential')
print('Exponential: ',R,p)
R, p=results.distribution_compare('power_law','stretched_exponential')
print('Stretched exponential: ',R,p)
R, p=results.distribution_compare('power_law','truncated_power_law')
print('Power law truncated: ',R,p)
R, p=results.distribution_compare('power_law','lognormal_positive')
print('Lognormal positive: ',R,p)
R, p=results.distribution_compare('power_law','lognormal')
print('Lognormal: ',R,p)
