# Oeffnet ein TUN (wie Android-VpnService.establish()), richtet es ein und startet Java mit dem fd.
import fcntl, os, struct, subprocess, sys
name, addr, route, fdarg = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, 0x400454ca, struct.pack("16sH22x", name.encode(), 0x0001 | 0x1000))
for c in (["ip", "addr", "add", addr, "dev", name], ["ip", "link", "set", name, "mtu", "1400", "up"], ["ip", "route", "add", route, "dev", name]):
    subprocess.run(c, check=True)
os.set_inheritable(fd, True)
cmd = [a.replace("{fd}", str(fd)) for a in fdarg]
os.execvp(cmd[0], cmd)
