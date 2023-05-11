#!/usr/bin/env python3

import argparse
import matplotlib.pyplot as plt
import matplotlib as mpl
import pandas as pd
import numpy as np
import os

# https://gist.github.com/thriveth/8560036
CB_color_cycle = ['#377eb8', '#ff7f00', '#4daf4a',
                  '#f781bf', '#a65628', '#984ea3',
                  '#999999', '#e41a1c', '#dede00']
# use with plot(..., colors=CB_color_cycle)

mpl.rcParams['pdf.fonttype'] = 42
mpl.rcParams['ps.fonttype'] = 42
mpl.rcParams['font.family'] = 'serif'
plt.style.use('tableau-colorblind10')


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze PLT times of the F-PKI web extension",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # source files
    parser.add_argument('sources', metavar='N', type=str, nargs='*', default=["plt-measurements.csv"])

    return parser.parse_args()


def save_fig(fig, name, folder=""):
    fig_folder = os.path.join("figures", folder)
    os.makedirs(fig_folder, exist_ok=True)
    fig.savefig(os.path.join(fig_folder, name), format='pdf', bbox_inches='tight')


def box_plots_relative_increase(d, metric, increase_type):
    fig, ax = plt.subplots()
    print(d.index.unique())
    indices = d.reset_index("domain").index.unique().drop([(False, '')])
    index = indices[1]
    print(d.xs(index)[f"{metric}-{increase_type}-inc"])
    ax.boxplot([d.xs(x)[f"{metric}-{increase_type}-inc"] for x in indices])
    ax.set_xticks(range(1, len(indices)+1), [str(x) for x in indices])
    ax.set_xlabel("Configuration")
    ax.grid()
    ax.set_yscale("log")
    if increase_type == "rel":
        min_exp = -2
        max_exp = 2
        ax.set_ylabel(f"relative increase in {metric}")
    else:
        min_exp = 0
        max_exp = 5
        ax.set_ylabel(f"increase in {metric} [in ms]")
    ax.set_ylim(pow(10, min_exp), pow(10, max_exp))
    save_fig(fig, f"box_plots_{metric}_{increase_type}_increase.pdf")


def main():
    args = parse_arguments()

    raw_data = pd.DataFrame()
    for x in args.sources:
        d = pd.read_csv(x)
        if len(args.sources) > 1:
            d["source"] = x
        raw_data = pd.concat([raw_data, d], ignore_index=True)

    # clean up data
    d = raw_data
    d["parsing"] = d["parsing"].fillna("")

    # add PLT column
    d["plt"] = d["time-to-first-byte"] + d["time-to-dom-completed"] + d["load-finished"]

    # calculate median values for each metric
    metrics = ["time-to-first-byte", "time-to-dom-completed", "load-finished", "plt"]
    d_med_groupby = d.groupby(["use-extension", "parsing", "domain"])
    d_med = d_med_groupby[metrics].median()
    d_med["n_success"] = d_med_groupby["status"].apply(lambda x: list(x).count("success"))
    d_med["n_failure"] = d_med_groupby["status"].apply(lambda x: list(x).count("failure"))

    # remove domains with insufficient measurement points
    d_domains = d_med[["n_success", "n_failure"]].groupby("domain").sum()
    incomplete_domains = d_domains[d_domains["n_failure"] > 0].index
    d_med = d_med.reset_index(["domain"])
    d_med = d_med[~d_med["domain"].isin(incomplete_domains)]
    d_med = d_med.set_index(["domain"], append=True)

    # find baseline latencies
    for col in metrics:
        d_med[f"{col}-baseline"] = pd.DataFrame(d_med[col]).apply(lambda x: d_med.xs(tuple([False, "", x.name[2]]))[col], axis=1)

    # find absolute increase in latencies
    for col in metrics:
        d_med[f"{col}-abs-inc"] = d_med[col] - d_med[f"{col}-baseline"]

    # find relative increase in latencies
    for col in metrics:
        d_med[f"{col}-rel-inc"] = d_med[f"{col}-abs-inc"] / d_med[f"{col}-baseline"]
        d_med[f"{col}-rel-inc"] = d_med[f"{col}-rel-inc"].fillna(0).replace(np.inf, 0)

    for col in metrics:
        box_plots_relative_increase(d_med, col, "rel")
        box_plots_relative_increase(d_med, col, "abs")


if __name__ == '__main__':
    main()
