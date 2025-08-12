# Sources

useful docs for eBPF/XDP things...

* `BPF_MAP_TYPE_HASH`: https://docs.ebpf.io/linux/map-type/BPF\_MAP\_TYPE\_HASH/
* `bpf_map_lookup_elem`: https://docs.ebpf.io/linux/helper-function/bpf\_map\_lookup\_elem/
* `bpf_for_each_map_elem`: https://docs.ebpf.io/linux/helper-function/bpf\_for\_each\_map\_elem/
* `bpf_map_update_elem`: https://docs.ebpf.io/linux/helper-function/bpf\_map\_update\_elem/
* `bpf_map_delete_elem`: https://docs.ebpf.io/linux/helper-function/bpf\_map\_delete\_elem/
* `bpf_ktime_get_boot_ns`: https://docs.ebpf.io/linux/helper-function/bpf\_ktime\_get\_boot\_ns/
* `bpf_htons`: https://docs.ebpf.io/ebpf-library/libbpf/ebpf/bpf\_htons/
* `struct xdp_md`: https://elixir.bootlin.com/linux/v6.16/source/include/uapi/linux/bpf.h#L6476
* `struct ethhdr`: https://elixir.bootlin.com/linux/v6.16/source/include/uapi/linux/if\_ether.h#L173
* `ETH_P_PAE`: https://elixir.bootlin.com/linux/v6.16/source/include/uapi/linux/if\_ether.h#L88
* EAP / EAPOL: https://support.huawei.com/enterprise/en/doc/EDOC1100086527
* `bpf_printk`: https://docs.ebpf.io/ebpf-library/libbpf/ebpf/bpf\_printk/
* variable-size `memcpy` issues: https://stackoverflow.com/questions/73088287/how-do-i-copy-data-to-buffer-in-ebpf
