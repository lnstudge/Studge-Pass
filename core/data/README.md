# Bundled data

## eff_large_wordlist.txt

The EFF large wordlist (7776 words), used by the passphrase generator. Fetched
unmodified from

    https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt

on 2026-11-04. Each line is the original `ddddd<TAB>word` form; the leading dice
number is ignored at runtime and kept so the file can be diffed against the
upstream copy.

Licence: the EFF wordlists are published under
[CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/) by the
Electronic Frontier Foundation. Attribution: *EFF Large Wordlist for Passphrases*,
Electronic Frontier Foundation. See D-0308 in `docs/DECISIONS.md`.

The file is compiled into the crate with `include_str!`, so a passphrase works
offline and never depends on a network fetch.
