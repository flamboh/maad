# MAAD

Source code for various Multifractal Address Anomaly Detection (MAAD) techniques.

For background see Misa et al., 2025: https://arxiv.org/pdf/2504.01374.

# Compile

Use nix:
```
$ nix-shell
$ ./compile.sh
```

Otherwise, find your own way to get `ghc` and required libraries listed in `shell.nix`, then `./compile.sh`.

# Usage

The main executable produced is called `MAAD`:
```
$ ./MAAD  --help
MAAD - Multifractal Address-space Anomaly Detection

Usage: MAAD --input FILEPATH --output FILEPATH_PREFIX [-t|--structure]
            [-s|--spectrum] [-d|--dimensions] [--csv] [-a|--addr-col COL]
            [-m|--meas-col COL] [--skip-first]

  Compute a combination of different multifractal analyses of a given set of IP
  addresses, optimally based on a per-address measure.

Available options:
  --input FILEPATH         File to read (csv or one address on each line).
  --output FILEPATH_PREFIX Prefix for output files.
  -t,--structure           Compute structure function
                           (OUT_PREFIX_structure.csv).
  -s,--spectrum            Compute multifractal spectrum
                           (OUT_PREFIX_spectrum.csv).
  -d,--dimensions          Compute generalized dimensions
                           (OUT_PREFIX_dimensions.csv).
  --csv                    Input file is csv (with multiple columns that need to
                           be parsed).
  -a,--addr-col COL        If input is a csv file, this (zero-based) column
                           contains the IP addresses to analyze. Default 0.
  -m,--meas-col COL        If the input is a csv file, this (zero-based) column
                           contains the measure associated with each IP address.
                           Default 1.
  --skip-first             Skip the first (header) row before reading the data.
  -h,--help                Show this help text
```

To read from stdin, use "-" as input filepath.

A couple example input files with lists of IPv4 addresses are included in `./test_data/` for testing.

There are also single analysis executables that write the resulting csv to stdout as described below (though these may get phased out later).

## Multifractal Spectrum

Usage:
```
$ ./Spectrum <input filepath>
```

Assumes the input file is a list of IPv4 addresses in dotted-decimal format (e.g., 192.0.2.1) with one address per line.

Outputs the estimated multifractal spectrum (f(alpha)) for the given list of addresses. See `Spectrum.hs` for details.

## Singularities

Usage:
```
$ ./Singularities <number of anomalous addresses to report> <input filepath>
```

Assumes the input file is a list of IPv4 addresses in dotted-decimal format (e.g., 192.0.2.1) with one address per line.

Outputs the addresses with highest and loweset alpha(x) estimated using least-squares. See `Singularities.hs` for details.


## Structure Function

Usage:
```
$ ./StructureFunction <input filepath>
```

Assumes the input file is a list of IPv4 addresses in dotted-decimal format (e.g., 192.0.2.1) with one address per line.

Not really an anomaly detection method. Outputs the estimated structure function (tauTilde(q)) for the given list of addresses along with estimated standard deviations. See `StructureFunction.hs` for details.


# Visualization

Scripts to generate plots of the structure and spectrum functions are included in the `./plots/` directory along with a wrapper script `./plots/plot.sh` that takes care of calling gnuplot with the right arguments.

For example, if you've saved the spectrum function in `spec.csv`, you could generate a plot by running
```
$ ./plots/plot.sh plots/spectrum.gnuplot spec.csv spec.svg
```

