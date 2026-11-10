// The few constants OpenVPN 3 Core's tun/win/tunutil.hpp needs, written here instead of pulling in
// tap-windows6 (GPL) for its header. This crate's tunnel is external, so Core never opens a TAP adapter.
// The values are Windows' network adapter class key and the TAP driver's documented ioctl numbers.
#pragma once

#include <winioctl.h>

#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define USERMODEDEVICEDIR "\\\\.\\Global\\"
#define TAP_WIN_SUFFIX ".tap"

#define TAP_WIN_CONTROL_CODE(request, method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_WIN_IOCTL_GET_VERSION TAP_WIN_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT TAP_WIN_CONTROL_CODE(5, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS TAP_WIN_CONTROL_CODE(6, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_GET_LOG_LINE TAP_WIN_CONTROL_CODE(8, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_CONFIG_TUN TAP_WIN_CONTROL_CODE(10, METHOD_BUFFERED)
