#!/usr/bin/env python

import matplotlib
import matplotlib as mpl
import matplotlib.pyplot as plt
from cycler import cycler

# set global settings
def pre_paper_plot(change=True):
    if not change:
        # Reset back to defaults
        #mpl.rcParams.update(mpl.rcParamsDefault)
        mpl.rcdefaults()
        # Apply own default config (as indicated in the matplotlibrc file)
        params = mpl.rc_params_from_file(mpl.matplotlib_fname())
        mpl.rcParams.update(params)
        return

    plt.rcParams['text.color'] = '000000'
    plt.rcParams['patch.facecolor'] = 'blue'
    plt.rcParams['patch.edgecolor'] = 'black'
    plt.rcParams['axes.facecolor'] = 'white'
    plt.rcParams['axes.edgecolor'] = 'black'
    plt.rcParams['axes.grid'] = False
    plt.rcParams['axes.labelcolor'] = 'black'
    #plt.rcParams['axes.color_cycle'] = '8cd0d3, 7f9f7f, cc9393, 93e0e3, dc8cc3, f0dfaf, dcdccc'
    plt.rcParams['axes.prop_cycle'] = cycler('color', ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf'])
    plt.rcParams['xtick.color'] = 'k'
    plt.rcParams['xtick.direction'] = 'in'
    plt.rcParams['ytick.color'] = 'k'
    plt.rcParams['ytick.direction'] = 'in'
    plt.rcParams['legend.fancybox'] = False
    plt.rcParams['figure.facecolor'] = 'white'
    plt.rcParams['figure.edgecolor'] = 'white'
    plt.rcParams['text.usetex'] = True

    plt.rcParams['figure.figsize'] = (8, 3)
    plt.rcParams['font.size'] = 10
    plt.rcParams['font.family'] = 'Computer Modern'
    plt.rcParams['axes.labelsize'] = 8
    plt.rcParams['axes.titlesize'] = 9
    plt.rcParams['legend.fontsize'] = 9
    plt.rcParams['xtick.labelsize'] = 7
    plt.rcParams['ytick.labelsize'] = 7
    plt.rcParams['savefig.dpi'] = 300
    plt.rcParams['xtick.major.size'] = 3
    plt.rcParams['xtick.minor.size'] = 3
    plt.rcParams['xtick.major.width'] = 1
    plt.rcParams['xtick.minor.width'] = 1
    plt.rcParams['ytick.major.size'] = 3
    plt.rcParams['ytick.minor.size'] = 3
    plt.rcParams['ytick.major.width'] = 1
    plt.rcParams['ytick.minor.width'] = 1
    plt.rcParams['legend.frameon'] = True
    plt.rcParams['legend.edgecolor'] = 'k'
    plt.rcParams['legend.loc'] = 'best'
    plt.rcParams['axes.linewidth'] = 1
    plt.rcParams['legend.handlelength'] = 3
    plt.rcParams['hatch.linewidth'] = 1

def post_paper_plot(change=True, bw_friendly=False, adjust_spines=False, sci_y=False):
    if not change:
        return
    if adjust_spines:
        plt.gca().spines['right'].set_color('none')
        plt.gca().spines['top'].set_color('none')
    plt.gca().xaxis.set_ticks_position('bottom')
    plt.gca().yaxis.set_ticks_position('left')
    if bw_friendly:
        setFigLinesBW(plt.gcf())
        setBarsBW(plt.gcf())
    if sci_y:
        # Change the Y axis to use a scientific notation and render it with LaTeX.
        formatter = matplotlib.ticker.ScalarFormatter(useMathText=True)
        formatter.set_powerlimits((-2,2))
        plt.gca().yaxis.set_major_formatter(formatter)

# Following functions taken from:
# https://stackoverflow.com/questions/7358118/matplotlib-black-white-colormap-with-dashes-dots-etc

def setAxLinesBW(ax):
    """
    Take each Line2D in the axes, ax, and convert the line style to be 
    suitable for black and white viewing.
    """
    marker_size = 4

    color_map = {
        '#1f77b4': {'marker': None, 'dash': (None,None)},
        '#ff7f0e': {'marker': None, 'dash': [2,1]},
        '#2ca02c': {'marker': None, 'dash': [3,1,1,1]},
        '#d62728': {'marker': None, 'dash': [3,1,1,1,1,1]},
        '#9467bd': {'marker': None, 'dash': [1,1]},
        '#8c564b': {'marker': None, 'dash': [4,1,2,0.5,0.3,0.5]},
        '#e377c2': {'marker': 'o', 'dash': (None,None)} #[1,2,1,10]}
        }


    lines_to_adjust = ax.get_lines()
    try:
        lines_to_adjust += ax.get_legend().get_lines()
    except AttributeError:
        pass

    for line in lines_to_adjust:
        orig_color = line.get_color()
        #line.set_color('black')
        try :
            line.set_dashes(color_map[orig_color]['dash'])
            line.set_marker(color_map[orig_color]['marker'])
            line.set_markersize(marker_size)
        except KeyError:
            print('Warning: could not add patterns to custom color "{}"'.format(orig_color))

def setFigLinesBW(fig):
    """
    Take each axes in the figure, and for each line in the axes, make the
    line viewable in black and white.
    """
    for ax in fig.get_axes():
        setAxLinesBW(ax)

def setBarsBW(fig):
    patterns = ['///', '---', '|||', '+++', '**', 'oo', '...']
    inx = 0
    boxes = []
    for ax in fig.get_axes():
        for child in ax.get_children():
            if isinstance(child, matplotlib.patches.Rectangle):
                boxes.append(child)
    # Skip the last rectangle which should be the background
    # Keep the same BW pattern when bars have the same color
    colors = dict()
    for box in boxes[:-1]:
        box_color = box.get_facecolor()
        #print(box_color)
        if(box_color in colors):
            box.set_hatch(colors[box_color])
        else:
            box.set_hatch(patterns[inx])
            colors[box_color] = patterns[inx]
            inx += 1
            if inx == len(patterns): inx = 0
