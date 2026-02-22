# xquic Baseline for mqvpn

This project pins a forked `xquic` as a git submodule.

## Fixed Upstream

- Submodule path: `third_party/xquic`
- Fork repository: `https://github.com/mp0rta/xquic.git`
- Branch: `feature/masque`
- Pinned commit hash: `0677b6c835c5f284ac167c89f8bc1622be47fa95`

## Reproducible Checkout

```bash
git clone --recurse-submodules https://github.com/mp0rta/mqvpn.git
cd mqvpn
git submodule update --init --recursive --checkout
git submodule status
```

Expected submodule status includes:

```text
0677b6c835c5f284ac167c89f8bc1622be47fa95 third_party/xquic
```

## Update Policy

When updating xquic:

1. Update `third_party/xquic` to a new tested commit in `feature/masque`.
2. Run smoke and multipath tests (`scripts/run_test.sh`, `scripts/run_multipath_test.sh`).
3. Update this file with the new pinned commit hash.
