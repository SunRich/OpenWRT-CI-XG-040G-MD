# XG-040G-MD UBI 固件构建

此配置用于已迁移到 pbs05 `uboot-an758x v2026.07-4` UBI/FIT 布局的 XG-040G-MD。

## 构建输入

- 原项目：`SunRich/OpenWRT-CI-XG-040G-MD`，工作分支 `codex/xg-custom-packages`。
- 固件源码：`bingoguo93/immortalwrt` 的 `6.18` 分支，本次固定到
  `1f7582d3d5cae8a2577a4d5c42ca081fedac8cf3`，在 `AIR-ALL.yml` 中设置。
- 唯一设备：`CONFIG_TARGET_DEVICE_airoha_an7581_DEVICE_nokia_xg-040g-md-ubi=y`。
- 保留 `Config/AIROHA-WIFI-NO.txt`、`Config/GENERAL.txt` 及原来的自定义包源。
- LuCI/Argon、Tailscale、OpenClash、WireGuard、DDNS-Go、Samba、自动重启和 NPU
  界面等仍使用原配置。UPnP、PCP/NAT-PMP、WOL 和集客仍显式禁用。

在 GitHub Actions 的 AIR-ALL 页面选择包含本次修改的分支，保持 TEST 关闭，运行完整构建。
产物发布在 GitHub Releases。`source-commit.txt` 与 `ci-commit.txt` 记录实际使用的源码。

## 构建检查

`Scripts/Validate-XG040G-UBI.py` 在 `make defconfig` 后确认设备与关键插件有效；
编译后检查每设备 manifest 和唯一的 `*-nokia_xg-040g-md-ubi-squashfs-sysupgrade.itb`：

1. FIT 所有镜像的数据范围、CRC/SHA 哈希有效，默认配置引用 ARM64 内核。
2. 根文件系统以 filesystem loadable 参与 FIT，内容是 SquashFS。
3. 内嵌设备树的首个 compatible 为 `nokia,xg-040g-md-ubi`。
4. NAND 分区：只读 all_flash 全片别名、只读 BL2 `[0, 0x20000)`、
   UBI `[0x20000, 0x10000000)`。
5. 设备树包含 fit、fip、bosa、ri、ubootenv、ubootenv2 卷，rootdisk 指向 fit。
6. 请求的关键软件实际存在于该设备的 manifest，禁用的软件没有重新进入镜像。

失败时停止发布。通过后发布 `ubi-compatibility.json` 和重命名后的 `SHA256SUMS`。
这与 U-Boot `net/lwip/httpd.c` 中的 FIT 校验对应，不能代替设备上的启动验证。

## 设备上的只读验证

下载产物并核对 SHA256SUMS；将系统 `.itb` 传到设备 `/tmp/`，执行
`sysupgrade -T /tmp/firmware.itb`。`-T` 只验证，不安装。
还需核对当前 `/proc/mtd`、UBI 卷和恢复页 U-Boot 版本。

获得明确的系统刷入指令后再安排安装与启动验证。此次重编译不需要重写 BL2、FIP、BOSA 或 RI。
官方 OpenWrt 的包不能跨内核版本复制到定制系统；旧配置应按服务恢复，避免覆盖新布局的升级逻辑。
