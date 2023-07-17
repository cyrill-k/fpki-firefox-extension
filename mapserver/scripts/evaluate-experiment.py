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


def fix_hist_step_vertical_line_at_end(ax):
    axpolygons = [
        poly for poly in ax.get_children() if isinstance(poly, mpl.patches.Polygon)
    ]
    for poly in axpolygons:
        poly.set_xy(poly.get_xy()[:-1])


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Mapserver plot script",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # source files
    parser.add_argument('sources', metavar='N', type=str, nargs='*', default=["measurements.csv"])

    return parser.parse_args()


def save_fig(fig, name, folder=""):
    fig_folder = os.path.join("figures", folder)
    os.makedirs(fig_folder, exist_ok=True)
    fig.savefig(os.path.join(fig_folder, name), format='pdf', bbox_inches='tight')


def filter_pk_type(d, public_key_type, replace_with_nan=False):
    rsa_indices = d["certificate_RSAPublicKey"] > 0
    ec_indices = (d["certificate_DSAPublicKey"] > 0) | (d["certificate_EllipticCurvePublicKey"] > 0) | (d["certificate_Ed25519PublicKey"] > 0) | (d["certificate_Ed448PublicKey"] > 0) | (d["certificate_X25519PublicKey"] > 0) | (d["certificate_X448PublicKey"] > 0)
    indices = None
    if public_key_type == "rsa":
        indices = rsa_indices & ~ec_indices
    if public_key_type == "ec":
        indices = ec_indices & ~rsa_indices
    if public_key_type == "mix":
        indices = rsa_indices & ec_indices
    if indices is None:
        raise ValueError()
    if replace_with_nan:
        d_replace = d.copy()
        d_replace[~indices] = np.nan
        return d_replace
    else:
        return d[indices]


def plot_size_comparison(raw_data, lim=None, logaxis=False, top_threshold=None):
    fig, ax = plt.subplots()
    # estimate size using the formula:
    # estimated = #certs*32 + #MHT proof hashes*32 + signature length
    raw_data["n_hashes"] = raw_data["sum_n_certificates"]+raw_data["sum_n_unique_intermediate_certificates"]+raw_data["sum_n_unique_root_certificates"]+raw_data["sum_proof_length"]
    raw_data["sum_signature_length"] = raw_data["signature_length"].apply(lambda x: sum(map(int, x.split(";"))))
    raw_data["estimated_hash_only_size"] = raw_data["n_hashes"]*32+raw_data["sum_signature_length"]
    raw_data["id_only"] = raw_data["estimated_hash_only_size"]/pow(10, 3)

    ax.hist(raw_data["id_only"].head(top_threshold) if top_threshold is not None else raw_data["id_only"], density=True, cumulative=True, bins=1000000, histtype='step', label="IDs only")
    raw_data["v0"] = raw_data["total_size"]/pow(10, 3)
    ax.hist(raw_data["v0"].head(top_threshold) if top_threshold is not None else raw_data["v0"], density=True, cumulative=True, bins=100000, histtype='step', label="full payload", linestyle="dotted")
    raw_data["v1"] = raw_data["total_size"]/pow(10, 3)+raw_data["estimated_hash_only_size"]/pow(10, 3)*3
    ax.hist(raw_data["v1"].head(top_threshold) if top_threshold is not None else raw_data["v1"], density=True, cumulative=True, bins=100000, histtype='step', label="overhead (IDs only, Q=3)", linestyle="dashed")
    raw_data["v2"] = raw_data["total_size"]/pow(10, 3)*3
    ax.hist(raw_data["v2"].head(top_threshold) if top_threshold is not None else raw_data["v2"], density=True, cumulative=True, bins=100000, histtype='step', label="overhead (Q=3)", linestyle="dashdot")
    fix_hist_step_vertical_line_at_end(ax)
    ax.set_xlim((pow(10, -0.9), pow(10, 4)))
    ax.set_xscale("log")
    ax.set_xlabel("Map server response size in KB")
    ax.set_ylabel("CDF")
    ax.grid()
    fix_hist_legend(ax, loc="lower right")
    save_fig(fig, f"total_size_comparison_threshold_{top_threshold}.pdf")


def fix_hist_legend(ax, **args):
    custom_lines = [mpl.lines.Line2D([0], [0], linestyle=x.get_linestyle(), color=mpl.colors.to_rgb(x.get_facecolor())) for x in ax.patches]
    labels = [x.get_label() for x in ax.patches]
    ax.legend(custom_lines, labels, **args)


def plot_total_size_no_lim(raw_data):
    fig, ax = plt.subplots()
    for x in ["rsa", "ec", "mix"]:
        ax.hist(filter_pk_type(raw_data, x)["total_size"]/pow(10, 3), density=True, cumulative=True, bins=100000, histtype='step', label=x)
    fix_hist_step_vertical_line_at_end(ax)
    ax.set_xscale("log")
    ax.set_xlabel("Mapserver response size in KB")
    ax.set_ylabel("CDF")
    ax.grid()
    ax.legend()
    save_fig(fig, "total_size.pdf")


def plot_total_size_rolling_window_combined(raw_data, window_size=1000):
    fig, ax = plt.subplots()
    raw_data["total_size_kb"] = raw_data["total_size"]/pow(10, 3)
    # ax.plot(raw_data["total_size_kb"].rolling(window_size).median())
    ax.plot(raw_data["total_size_kb"].rolling(window_size, center=True).quantile(0.95), label="95th percentile")
    ax.plot(raw_data["total_size_kb"].rolling(window_size, center=True).median(), label="median", linestyle="dashed")
    # for x in ["rsa", "mix"]:
        # print(x)
        # print(filter_pk_type(raw_data, x, replace_with_nan=True).count())
        # d_filtered = filter_pk_type(raw_data, x, replace_with_nan=True)["total_size_kb"]
        # ax.plot(f_agg(d_filtered.rolling(window_size, min_periods=3, center=True)), label=f"{x}: {d_filtered.count()}")
    # ax.plot(raw_data["total_size_kb"].rolling(window_size).median())
    ax.set_ylim((1, pow(10,3)))
    ax.set_ylabel("Map server payload size in KB")
    ax.set_xlabel(f"Rolling window ({window_size} entries) over Alexa top 100K domains")
    ax.set_yscale("log")
    ax.grid()
    ax.legend()
    save_fig(fig, f"total_size_rolling_window_{window_size}_combined.pdf")


def plot_total_size_rolling_window(raw_data, window_size=1000, agg="median"):
    def f_agg(x):
        if agg == "median":
            return x.median()
        elif agg == "mean":
            return x.mean()
        elif agg == "p95":
            return x.quantile(0.95)
        else:
            raise ValueError()
    fig, ax = plt.subplots()
    raw_data["total_size_kb"] = raw_data["total_size"]/pow(10, 3)
    # ax.plot(raw_data["total_size_kb"].rolling(window_size).median())
    ax.plot(f_agg(raw_data["total_size_kb"].rolling(window_size, min_periods=3, center=True)), label=f"all: {raw_data['total_size_kb'].count()}")
    # for x in ["rsa", "mix"]:
        # print(x)
        # print(filter_pk_type(raw_data, x, replace_with_nan=True).count())
        # d_filtered = filter_pk_type(raw_data, x, replace_with_nan=True)["total_size_kb"]
        # ax.plot(f_agg(d_filtered.rolling(window_size, min_periods=3, center=True)), label=f"{x}: {d_filtered.count()}")
    # ax.plot(raw_data["total_size_kb"].rolling(window_size).median())
    ax.set_ylim((10, None))
    ax.set_ylabel(f"{agg} mapserver response size in KB")
    ax.set_xlabel(f"Rolling window ({window_size} entries) over Alexa top 100K domains")
    ax.set_yscale("log")
    ax.grid()
    ax.legend()
    save_fig(fig, f"total_size_rolling_window_{window_size}_{agg}.pdf")


def plot_hash_size_only(raw_data, lim=None, logaxis=False):
    fig, ax = plt.subplots()
    # estimate size using the formula:
    # estimated = #certs*32 + #MHT proof hashes*32 + signature length
    raw_data["n_hashes"] = raw_data["sum_n_certificates"]+raw_data["sum_n_unique_intermediate_certificates"]+raw_data["sum_n_unique_root_certificates"]+raw_data["sum_proof_length"]
    raw_data["sum_signature_length"] = raw_data["signature_length"].apply(lambda x: sum(map(int, x.split(";"))))
    raw_data["estimated_hash_only_size"] = raw_data["n_hashes"]*32+raw_data["sum_signature_length"]
    ax.hist(raw_data["estimated_hash_only_size"]/pow(10, 3), density=True, cumulative=True, bins=1000000, histtype='step')
    fix_hist_step_vertical_line_at_end(ax)
    ax.set_xlabel("Estimated Mapserver response size in KB (hashes only)")
    ax.set_ylabel("CDF")

    name = "total_size_hash_only"
    if logaxis:
        ax.set_xscale("log")
        name += "_log"
    ax.set_xlim((1 if logaxis else 0, lim))
    if lim is not None:
        name += f"_lim_{lim}"
    ax.grid()
    save_fig(fig, f"{name}.pdf")


def plot_total_size(raw_data):
    fig, ax = plt.subplots()
    ax.hist(raw_data["total_size"]/pow(10, 3), density=True, cumulative=True, bins=100000, histtype='step')
    fix_hist_step_vertical_line_at_end(ax)
    ax.set_xlim((0, 200))
    ax.set_xlabel("Mapserver response size in KB")
    ax.set_ylabel("CDF")
    ax.grid()
    save_fig(fig, "total_size_lim_200.pdf")


def plot_proof_size(raw_data):
    fig, ax = plt.subplots()
    print(raw_data["sum_proof_length"])
    ax.hist(raw_data["sum_proof_length"], density=True, cumulative=True, bins=1000, histtype='step')
    fix_hist_step_vertical_line_at_end(ax)
    # ax.set_xlim((0, 100))
    ax.set_xlabel("Proof length")
    ax.set_ylabel("CDF")
    ax2 = ax.twiny()
    ax2.hist(raw_data["sum_proof_length"]*32/1000, density=True, cumulative=True, bins=1000, histtype='step')
    ax2.set_xlabel("Proof size in KB")
    fix_hist_step_vertical_line_at_end(ax2)
    ax.grid()
    save_fig(fig, "proof_size.pdf")


def plot_status(raw_data):
    fig, ax = plt.subplots()
    status_df = raw_data.groupby("status").count()["rank"]
    bars = ax.bar(list(map(str, status_df.index)), status_df)
    print(status_df.values)
    ax.bar_label(bars)
    ax.set_xlabel("HTTP return status")
    save_fig(fig, "status.pdf")


def plot_n_domains(raw_data):
    fig, ax = plt.subplots()
    n_domains_df = raw_data["n_certificates"].apply(lambda x: len(x.split(";"))).to_frame("n_domains")
    n_domains_df["dummy"] = 1
    n_domains_df = n_domains_df.groupby("n_domains").count()["dummy"]
    bars = ax.bar(n_domains_df.index, n_domains_df)
    ax.bar_label(bars)
    ax.set_yscale("log")
    save_fig(fig, "n_domains.pdf")


def plot_n_certificates_no_lim(raw_data):
    fig, ax = plt.subplots()
    ax.hist(raw_data["sum_n_certificates"], density=True, cumulative=True, bins=1000000, histtype='step')
    fix_hist_step_vertical_line_at_end(ax)
    ax.set_xlabel("number of leaf certificates per mapserver response")
    ax.set_ylabel("CDF")
    ax.set_xscale("log")
    ax.set_xlim((1, None))
    ax.grid()
    save_fig(fig, "n_certificates.pdf")


def plot_n_certificates(raw_data):
    fig, ax = plt.subplots()
    ax.hist(raw_data["sum_n_certificates"], density=True, cumulative=True, bins=range(1000), histtype='step')
    fix_hist_step_vertical_line_at_end(ax)
    ax.set_xlim((0, 10))
    ax.set_xlabel("number of leaf certificates per mapserver response")
    ax.set_ylabel("CDF")
    ax.grid()
    save_fig(fig, "n_certificates_lim_10.pdf")


def main():
    # df = pd.DataFrame([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    # df_fil = df.copy()
    # df_fil[df_fil[0] == 4] = np.nan
    # print(df)
    # print(df_fil)
    
    # print(df[df[0] == 4])
    # print(df.rolling(3, min_periods=1).mean())
    # exit(2)

    
    args = parse_arguments()

    raw_data = pd.DataFrame()
    for x in args.sources:
        d = pd.read_csv(x)
        if len(args.sources) > 1:
            d["source"] = x
        raw_data = pd.concat([raw_data, d], ignore_index=True)

    plot_status(raw_data)
    success_df = raw_data[raw_data["status"] == 201]
    print(success_df)
    plot_size_comparison(success_df, top_threshold=1000)
    plot_size_comparison(success_df)
    plot_total_size_rolling_window_combined(success_df)
    plot_hash_size_only(success_df, logaxis=True)
    plot_hash_size_only(success_df, lim=10)
    plot_total_size_rolling_window(success_df, agg="median")
    plot_total_size_rolling_window(success_df, agg="mean")
    plot_total_size_rolling_window(success_df, agg="p95")
    plot_total_size_no_lim(success_df)
    plot_total_size(success_df)
    plot_proof_size(success_df)
    plot_n_certificates_no_lim(success_df)
    plot_n_certificates(success_df)
    plot_n_domains(success_df)


if __name__ == '__main__':
    main()
