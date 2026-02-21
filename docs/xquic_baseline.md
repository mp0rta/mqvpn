# xquic Baseline for mqvpn

This project pins a forked `xquic` as a git submodule.

## Fixed Upstream

- Submodule path: `third_party/xquic`
- Fork repository: `https://github.com/mp0rta/xquic.git`
- Branch: `feature/masque`
- Pinned commit hash: `34e5beec0e1af4af8444384788289fd8d6738dbd`

## Reproducible Checkout

```bash
git clone --recurse-submodules https://github.com/mp0rta/mqvpn.git
cd mqvpn
git submodule update --init --recursive --checkout
git submodule status
```

Expected submodule status includes:

```text
34e5beec0e1af4af8444384788289fd8d6738dbd third_party/xquic
```

## Update Policy

When updating xquic:

1. Update `third_party/xquic` to a new tested commit in `feature/masque`.
2. Run smoke and multipath tests (`scripts/run_test.sh`, `scripts/run_multipath_test.sh`).
3. Update this file with the new pinned commit hash.
