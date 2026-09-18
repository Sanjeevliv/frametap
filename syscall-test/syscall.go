//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// htons converts a 16-bit integer from host byte order to network byte order (Big Endian).
func htons(i uint16) int {
	return int((i<<8)&0xff00 | (i>>8)&0x00ff)
}

func main() {
	fd, err := unix.Socket(
		unix.AF_PACKET,
		unix.SOCK_RAW,
		htons(unix.ETH_P_ALL),
	)

	if err != nil {
		panic(err)
	}

	fmt.Println("socket fd:", fd)

	unix.Close(fd)
}
