BEGIN {
	dmn = 0
	B36 = "0123456789abcdefghijklmnopqrstuvwxyz"
	ips = 0
	pip = 0
	DMNF = "./conf/rules_azd.yaml"
	IPCF = "./conf/rules_azi.yaml"
	SPCF = "./conf/rules_azs.yaml"
	spc = 0
}

dmn == 0 {
	if (/^domains/) {
		dmn = 1
		print("payload:")
	}
	next
}

dmn == 1 && /;/ {
	dmn = 2
	next
}

dmn == 1 {
	if (/^[[:space:]]*"/) {
		split($0, t, /"/)
		tld = t[2]
		delete t
		next
	}
	if (/^[[:space:]]*[[:digit:]]/) {
		split($0, t, /[:"[:space:]]+/)
		for (i = 1; i < length(t[3]) + 1; i += t[2]) {
			print("  - DOMAIN-SUFFIX," substr(t[3], i, t[2]) "." tld)
		}
		delete t
		next
	}
}

ips == 0 {
	if (/d_ipaddr/) {
		ips = 1
		print("payload:") > IPCF
	}
	next
}

ips == 1 && /"/ {
	ips = 2
	next
}

ips == 1 {
	split($0, t, /[^0-9a-z]+/)
	for (i = 1; i <= length(t); ++i) {
		#print i, t[i]
		if (length(t[i]) > 0) {
			cip = pip
			for (j = length(t[i]); j > 0; j--) {
				cip += (index(B36, substr(t[i], j, 1)) - 1) * 36 ^ (length(t[i]) - j)
			}
			#printf "%s\t%d\t%d\t", t[i], pip, cip
			pip = cip
			printf("  - '") >> IPCF
			for (j = 256 ^ 3; j >= 1; j /= 256) {
				#printf "%d",int(cip/j)
				printf("%d", int(cip / j)) >> IPCF
				if (j != 1) {
					#printf "."
					printf(".") >> IPCF
				}
				cip %= j
			}
			#print "/32'"
			print("/32'") >> IPCF
		}
	}
	delete t
	next
}

spc == 0 {
	if (/^var +special +=/) {
		spc = 1
		print("payload:") > SPCF
	}
	next
}

spc == 1 && /;/ {
	spc = 2
	exit
}

spc == 1 {
	split($0, t, /\] *, *\[/)
	for (j = 1; j <= length(t); ++j) {
		gsub(/[^0-9.,]+/, "", t[j])
		sub(/,/, "/", t[j])
		print("  - '" t[j] "'") >> SPCF
	}
	delete t
}
