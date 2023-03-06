# SoConnect

**SoConnect** (SC) is a framework for fastly developping DPDK application, which integrate DOCA and CUDA support, one can use this framework for rapidly developping your own network functionality that can be deployed on either x86 server or ARM SoC.


## Preparation

1. Install DPDK and setup DPDK environment (e.g. hugepage, etc.)

2. Install other dependencies

```bash
sudo apt-get install libgmp3-dev
```

3. (Optional) DOCA support

TODO

4. (Optional) CUDA support

TODO

## Develop

1. add configuration file to `conf/apps`

2. add header to `include/apps/`

3. add source file to `src/apps/`

4. change the selected application inside `meson.build`