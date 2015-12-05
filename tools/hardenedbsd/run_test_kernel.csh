#!/bin/csh

set VM_RUN="/tmp/vmrun-hbsd.sh"

kldload -n vmm

if ( ! -e ${VM_RUN} ) then
	cp /usr/share/examples/bhyve/vmrun.sh ${VM_RUN}
	chmod +x ${VM_RUN}
endif

${VM_RUN} -d /tmp/hbsd.raw test
