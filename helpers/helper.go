package helpers

import "net"

func GetLoopbakInterface() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	var name string
loop:
	for _, i := range interfaces {
		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			if addr.(*net.IPNet).IP.IsLoopback() {
				name = i.Name
				break loop
			}
		}
	}

	return name, nil
}
