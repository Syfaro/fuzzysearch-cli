# fuzzysearch-cli

A tool to batch search images against [FuzzySearch](https://fuzzysearch.net).

## Usage

First, you must obtain an API token for FuzzySearch. You can then run the tool
like follows:

```bash
fuzzysearch-cli --api-key abc123 /path/to/images per-file sources.csv
```

This will create a file named sources.csv. This CSV file contains a full path to
each image and space separated links to each known source.

More information about the tool's use can be found with the `--help` flag.

It is also possible to use a FuzzySearch database dump to perform all searches
locally. Use the `--database-path` option instead of `--api-key`.

## Details

It caches details about each path's hash and each hash's matches indefinitely.
This allows for very quick incremental updates.
