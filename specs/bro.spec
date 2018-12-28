#  144  rsync -aP /usr/share/defaults/bro/scripts /etc/bro
#  146  rsync -aP /usr/share/defaults/bro/config /etc/bro
# why it does not exist?
#  151  useradd -m bro
#  157  setcap cap_net_raw+ep /usr/bin/bro
#  160  cd /etc/bro/config/
#  168  mkdir -p /var/log/nsm/bro
#  169  chown -Rv bro:bro /var/log/nsm/bro
#  172  mkdir -p /var/lib/bro
#  173  chown -Rv bro:bro /var/lib/bro

Name     : bro
Version  : 2.5.9271b2032
Release  : 3
URL      : https://bro.org
Source0  : http://clb0.security.allizom.org/bro-2.5.9271b2032.tar
Patch0   : pthread.patch
Summary  : Bro is a powerful framework for network analysis and security monitoring
Group    : Development/Tools
License  : BSD-3-Clause

%description
Bro is a powerful network analysis framework that is much different from the
typical IDS you may know.  While focusing on network security monitoring, Bro
provides a comprehensive platform for more general network traffic analysis as
well. Well grounded in more than 15 years of research, Bro has successfully
bridged the traditional gap between academia and operations since its
inception. Today, it is relied upon operationally in particular by many
scientific environments for securing their cyberinfrastructure. Bro's user
community includes major universities, research labs, supercomputing centers,
and open-science communities.

%package bin
Summary:        The core bro installation without broctl
Group:          Productivity/Networking/Diagnostic

%description bin
Bro is a powerful network analysis framework that is much different from the
typical IDS you may know.  While focusing on network security monitoring, Bro
provides a comprehensive platform for more general network traffic analysis as
well. Well grounded in more than 15 years of research, Bro has successfully
bridged the traditional gap between academia and operations since its
inception. Today, it is relied upon operationally in particular by many
scientific environments for securing their cyberinfrastructure. Bro's user
community includes major universities, research labs, supercomputing centers,
and open-science communities.

%package data
Summary:        The core bro installation without broctl
Group:          Productivity/Networking/Diagnostic

%description data
The base set of Bro scripts

%package dev
Summary:        The core bro installation without broctl
Group:          Productivity/Networking/Diagnostic

%description dev
Development headers for Bro

%package -n libbroccoli
Summary:        Broccoli library
Group:          System/Libraries

%description -n libbroccoli
Broccoli is the "Bro client communications library". It allows you
to create client sensors for the Bro intrusion detection system.
Broccoli can speak a good subset of the Bro communication protocol,
in particular, it can receive Bro IDs, send and receive Bro events,
and send and receive event requests to/from peering Bros. You can
currently create and receive values of pure types like integers,
counters, timestamps, IP addresses, port numbers, booleans, and
strings.

%package -n libbroccoli-data
Summary:        Broccoli library
Group:          System/Libraries

%description -n libbroccoli-data
Broccoli configuration files

%package -n libbroccoli-dev
Summary:        Development files for broccoli
Group:          Development/Libraries/C and C++
Requires:       libbroccoli = %{version}

%description -n libbroccoli-dev
Development headers for libbroccoli.

%package -n broctl
Summary:        Bro Control
Group:          Productivity/Networking/Diagnostic
Requires:       python
Requires:       libbroccoli = %{version}
Requires:       bro-bin = %{version}

%description -n broctl
BroControl is Bro's interactive shell for operating Bro installations.

%package -n broctl-data
Summary:        Bro Control
Group:          Productivity/Networking/Diagnostic

%description -n broctl-data
Broctl configuration files

%package -n broker
Summary:        Bro Control
Group:          Productivity/Networking/Diagnostic

%description -n broker
The broker library

%package -n broker-dev
Summary:        Bro Control
Group:          Productivity/Networking/Diagnostic

%description -n broker-dev
Development headers for broker

%pre
/usr/bin/getent group bro >/dev/null || /usr/sbin/groupadd -r bro

%pre bin
/usr/bin/getent group bro >/dev/null || /usr/sbin/groupadd -r bro

%pre -n broctl
/usr/bin/getent group bro >/dev/null || /usr/sbin/groupadd -r bro

%pre -n libbroccoli
/usr/bin/getent group bro >/dev/null || /usr/sbin/groupadd -r bro

%pre -n libbroccoli-dev
/usr/bin/getent group bro >/dev/null || /usr/sbin/groupadd -r bro

%prep
%setup
%patch0 -p1

%build
export LANG=C
#./configure --prefix=%{_prefix} --binary-package --scriptdir=/etc/bro/scripts --localstatedir=/var/lib/bro --spooldir=/var/lib/bro --logdir=/var/log/nsm/bro --conf-files-dir=/etc/bro/config --with-libcaf=/usr/lib --enable-perftools --disable-broker
./configure --prefix=%{_prefix} --binary-package --scriptdir=/etc/bro/scripts --localstatedir=/var/lib/bro --spooldir=/var/lib/bro --logdir=/var/log/nsm/bro --conf-files-dir=/etc/bro/config --enable-perftools --disable-broker
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
mkdir -p %{buildroot}/usr/share/defaults/bro
mv %{buildroot}/etc/bro/scripts %{buildroot}/usr/share/defaults/bro
mv %{buildroot}/etc/bro/config %{buildroot}/usr/share/defaults/bro
rm -rf %{buildroot}/usr/lib/broctl/BroControl/__pycache__
rm -rf %{buildroot}/usr/lib/broctl/__pycache__
rm -rf %{buildroot}/usr/lib/broctl/plugins/__pycache__
# mkdir spool dir?
# mkdir log dir?

%post -n libbroccoli -p /sbin/ldconfig

%postun -n libbroccoli -p /sbin/ldconfig

%files

%files bin
%defattr(-,root,root,-)
/usr/bin/bro
/usr/bin/bro-config
/usr/bin/bro-cut
/usr/bin/broctl
/usr/bin/capstats
/usr/bin/trace-summary
/usr/bin/adtrace
/usr/bin/rst

%files data
%defattr(-,root,root,-)
/usr/share/defaults/bro/config/networks.cfg
/usr/share/defaults/bro/config/node.cfg
/usr/share/defaults/bro/scripts/base/bif/__load__.bro
/usr/share/defaults/bro/scripts/base/bif/analyzer.bif.bro
/usr/share/defaults/bro/scripts/base/bif/bloom-filter.bif.bro
/usr/share/defaults/bro/scripts/base/bif/bro.bif.bro
/usr/share/defaults/bro/scripts/base/bif/broxygen.bif.bro
/usr/share/defaults/bro/scripts/base/bif/cardinality-counter.bif.bro
/usr/share/defaults/bro/scripts/base/bif/comm.bif.bro
/usr/share/defaults/bro/scripts/base/bif/const.bif.bro
/usr/share/defaults/bro/scripts/base/bif/data.bif.bro
/usr/share/defaults/bro/scripts/base/bif/event.bif.bro
/usr/share/defaults/bro/scripts/base/bif/file_analysis.bif.bro
/usr/share/defaults/bro/scripts/base/bif/input.bif.bro
/usr/share/defaults/bro/scripts/base/bif/logging.bif.bro
/usr/share/defaults/bro/scripts/base/bif/messaging.bif.bro
/usr/share/defaults/bro/scripts/base/bif/option.bif.bro
/usr/share/defaults/bro/scripts/base/bif/pcap.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_ARP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_AsciiReader.ascii.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_AsciiWriter.ascii.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_BackDoor.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_BenchmarkReader.benchmark.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_BinaryReader.binary.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_BitTorrent.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_ConfigReader.config.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_ConnSize.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_ConnSize.functions.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_DCE_RPC.consts.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_DCE_RPC.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_DCE_RPC.types.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_DHCP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_DNP3.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_DNS.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_FTP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_FTP.functions.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_File.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_FileEntropy.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_FileExtract.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_FileExtract.functions.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_FileHash.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_Finger.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_GSSAPI.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_GTPv1.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_Gnutella.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_HTTP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_HTTP.functions.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_ICMP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_IMAP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_IRC.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_Ident.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_InterConn.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_KRB.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_KRB.types.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_Login.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_Login.functions.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_MIME.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_Modbus.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_MySQL.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_NCP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_NTLM.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_NTLM.types.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_NTP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_NetBIOS.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_NetBIOS.functions.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_NoneWriter.none.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_PE.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_POP3.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_RADIUS.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_RDP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_RDP.types.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_RFB.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_RPC.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_RawReader.raw.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SIP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.consts.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_check_directory.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_close.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_create_directory.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_echo.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_logoff_andx.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_negotiate.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_nt_cancel.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_nt_create_andx.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_query_information.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_read_andx.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_session_setup_andx.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_transaction.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_transaction2.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_transaction2_secondary.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_transaction_secondary.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_tree_connect_andx.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_tree_disconnect.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_com_write_andx.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb1_events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb2_com_close.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb2_com_create.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb2_com_negotiate.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb2_com_read.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb2_com_session_setup.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb2_com_set_info.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb2_com_tree_connect.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb2_com_tree_disconnect.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb2_com_write.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.smb2_events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMB.types.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMTP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SMTP.functions.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SNMP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SNMP.types.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SOCKS.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SQLiteReader.sqlite.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SQLiteWriter.sqlite.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SSH.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SSH.types.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SSL.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SSL.functions.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SSL.types.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_SteppingStone.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_Syslog.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_TCP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_TCP.functions.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_Teredo.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_UDP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_Unified2.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_Unified2.types.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_X509.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_X509.functions.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_X509.ocsp_events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_X509.types.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/Bro_XMPP.events.bif.bro
/usr/share/defaults/bro/scripts/base/bif/plugins/__load__.bro
/usr/share/defaults/bro/scripts/base/bif/reporter.bif.bro
/usr/share/defaults/bro/scripts/base/bif/stats.bif.bro
/usr/share/defaults/bro/scripts/base/bif/store.bif.bro
/usr/share/defaults/bro/scripts/base/bif/strings.bif.bro
/usr/share/defaults/bro/scripts/base/bif/top-k.bif.bro
/usr/share/defaults/bro/scripts/base/bif/types.bif.bro
/usr/share/defaults/bro/scripts/base/files/extract/__load__.bro
/usr/share/defaults/bro/scripts/base/files/extract/main.bro
/usr/share/defaults/bro/scripts/base/files/hash/__load__.bro
/usr/share/defaults/bro/scripts/base/files/hash/main.bro
/usr/share/defaults/bro/scripts/base/files/pe/__load__.bro
/usr/share/defaults/bro/scripts/base/files/pe/consts.bro
/usr/share/defaults/bro/scripts/base/files/pe/main.bro
/usr/share/defaults/bro/scripts/base/files/unified2/__load__.bro
/usr/share/defaults/bro/scripts/base/files/unified2/main.bro
/usr/share/defaults/bro/scripts/base/files/x509/__load__.bro
/usr/share/defaults/bro/scripts/base/files/x509/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/analyzer/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/analyzer/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/broker/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/broker/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/broker/store.bro
/usr/share/defaults/bro/scripts/base/frameworks/cluster/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/cluster/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/cluster/nodes/logger.bro
/usr/share/defaults/bro/scripts/base/frameworks/cluster/nodes/manager.bro
/usr/share/defaults/bro/scripts/base/frameworks/cluster/nodes/proxy.bro
/usr/share/defaults/bro/scripts/base/frameworks/cluster/nodes/worker.bro
/usr/share/defaults/bro/scripts/base/frameworks/cluster/setup-connections.bro
/usr/share/defaults/bro/scripts/base/frameworks/communication/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/communication/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/config/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/config/input.bro
/usr/share/defaults/bro/scripts/base/frameworks/config/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/control/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/control/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/dpd/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/dpd/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/files/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/files/magic/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/files/magic/archive.sig
/usr/share/defaults/bro/scripts/base/frameworks/files/magic/audio.sig
/usr/share/defaults/bro/scripts/base/frameworks/files/magic/font.sig
/usr/share/defaults/bro/scripts/base/frameworks/files/magic/general.sig
/usr/share/defaults/bro/scripts/base/frameworks/files/magic/image.sig
/usr/share/defaults/bro/scripts/base/frameworks/files/magic/libmagic.sig
/usr/share/defaults/bro/scripts/base/frameworks/files/magic/msoffice.sig
/usr/share/defaults/bro/scripts/base/frameworks/files/magic/video.sig
/usr/share/defaults/bro/scripts/base/frameworks/files/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/input/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/input/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/input/readers/ascii.bro
/usr/share/defaults/bro/scripts/base/frameworks/input/readers/benchmark.bro
/usr/share/defaults/bro/scripts/base/frameworks/input/readers/binary.bro
/usr/share/defaults/bro/scripts/base/frameworks/input/readers/config.bro
/usr/share/defaults/bro/scripts/base/frameworks/input/readers/raw.bro
/usr/share/defaults/bro/scripts/base/frameworks/input/readers/sqlite.bro
/usr/share/defaults/bro/scripts/base/frameworks/intel/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/intel/cluster.bro
/usr/share/defaults/bro/scripts/base/frameworks/intel/files.bro
/usr/share/defaults/bro/scripts/base/frameworks/intel/input.bro
/usr/share/defaults/bro/scripts/base/frameworks/intel/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/logging/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/logging/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/logging/postprocessors/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/logging/postprocessors/scp.bro
/usr/share/defaults/bro/scripts/base/frameworks/logging/postprocessors/sftp.bro
/usr/share/defaults/bro/scripts/base/frameworks/logging/writers/ascii.bro
/usr/share/defaults/bro/scripts/base/frameworks/logging/writers/none.bro
/usr/share/defaults/bro/scripts/base/frameworks/logging/writers/sqlite.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/catch-and-release.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/cluster.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/drop.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/non-cluster.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/plugin.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/plugins/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/plugins/acld.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/plugins/broker.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/plugins/debug.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/plugins/openflow.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/plugins/packetfilter.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/shunt.bro
/usr/share/defaults/bro/scripts/base/frameworks/netcontrol/types.bro
/usr/share/defaults/bro/scripts/base/frameworks/notice/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/notice/actions/add-geodata.bro
/usr/share/defaults/bro/scripts/base/frameworks/notice/actions/drop.bro
/usr/share/defaults/bro/scripts/base/frameworks/notice/actions/email_admin.bro
/usr/share/defaults/bro/scripts/base/frameworks/notice/actions/page.bro
/usr/share/defaults/bro/scripts/base/frameworks/notice/actions/pp-alarms.bro
/usr/share/defaults/bro/scripts/base/frameworks/notice/cluster.bro
/usr/share/defaults/bro/scripts/base/frameworks/notice/extend-email/hostnames.bro
/usr/share/defaults/bro/scripts/base/frameworks/notice/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/notice/non-cluster.bro
/usr/share/defaults/bro/scripts/base/frameworks/notice/weird.bro
/usr/share/defaults/bro/scripts/base/frameworks/openflow/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/openflow/cluster.bro
/usr/share/defaults/bro/scripts/base/frameworks/openflow/consts.bro
/usr/share/defaults/bro/scripts/base/frameworks/openflow/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/openflow/non-cluster.bro
/usr/share/defaults/bro/scripts/base/frameworks/openflow/plugins/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/openflow/plugins/broker.bro
/usr/share/defaults/bro/scripts/base/frameworks/openflow/plugins/log.bro
/usr/share/defaults/bro/scripts/base/frameworks/openflow/plugins/ryu.bro
/usr/share/defaults/bro/scripts/base/frameworks/openflow/types.bro
/usr/share/defaults/bro/scripts/base/frameworks/packet-filter/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/packet-filter/cluster.bro
/usr/share/defaults/bro/scripts/base/frameworks/packet-filter/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/packet-filter/netstats.bro
/usr/share/defaults/bro/scripts/base/frameworks/packet-filter/utils.bro
/usr/share/defaults/bro/scripts/base/frameworks/reporter/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/reporter/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/signatures/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/signatures/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/software/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/software/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/cluster.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/main.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/non-cluster.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/average.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/hll_unique.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/last.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/max.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/min.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/sample.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/std-dev.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/sum.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/topk.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/unique.bro
/usr/share/defaults/bro/scripts/base/frameworks/sumstats/plugins/variance.bro
/usr/share/defaults/bro/scripts/base/frameworks/tunnels/__load__.bro
/usr/share/defaults/bro/scripts/base/frameworks/tunnels/main.bro
/usr/share/defaults/bro/scripts/base/init-bare.bro
/usr/share/defaults/bro/scripts/base/init-default.bro
/usr/share/defaults/bro/scripts/base/misc/find-checksum-offloading.bro
/usr/share/defaults/bro/scripts/base/misc/find-filtered-trace.bro
/usr/share/defaults/bro/scripts/base/misc/p0f.fp
/usr/share/defaults/bro/scripts/base/misc/version.bro
/usr/share/defaults/bro/scripts/base/protocols/conn/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/conn/contents.bro
/usr/share/defaults/bro/scripts/base/protocols/conn/inactivity.bro
/usr/share/defaults/bro/scripts/base/protocols/conn/main.bro
/usr/share/defaults/bro/scripts/base/protocols/conn/polling.bro
/usr/share/defaults/bro/scripts/base/protocols/conn/thresholds.bro
/usr/share/defaults/bro/scripts/base/protocols/dce-rpc/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/dce-rpc/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/dce-rpc/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/dce-rpc/main.bro
/usr/share/defaults/bro/scripts/base/protocols/dhcp/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/dhcp/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/dhcp/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/dhcp/main.bro
/usr/share/defaults/bro/scripts/base/protocols/dhcp/utils.bro
/usr/share/defaults/bro/scripts/base/protocols/dnp3/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/dnp3/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/dnp3/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/dnp3/main.bro
/usr/share/defaults/bro/scripts/base/protocols/dns/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/dns/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/dns/main.bro
/usr/share/defaults/bro/scripts/base/protocols/ftp/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/ftp/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/ftp/files.bro
/usr/share/defaults/bro/scripts/base/protocols/ftp/gridftp.bro
/usr/share/defaults/bro/scripts/base/protocols/ftp/info.bro
/usr/share/defaults/bro/scripts/base/protocols/ftp/main.bro
/usr/share/defaults/bro/scripts/base/protocols/ftp/utils-commands.bro
/usr/share/defaults/bro/scripts/base/protocols/ftp/utils.bro
/usr/share/defaults/bro/scripts/base/protocols/http/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/http/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/http/entities.bro
/usr/share/defaults/bro/scripts/base/protocols/http/files.bro
/usr/share/defaults/bro/scripts/base/protocols/http/main.bro
/usr/share/defaults/bro/scripts/base/protocols/http/utils.bro
/usr/share/defaults/bro/scripts/base/protocols/imap/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/imap/main.bro
/usr/share/defaults/bro/scripts/base/protocols/irc/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/irc/dcc-send.bro
/usr/share/defaults/bro/scripts/base/protocols/irc/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/irc/files.bro
/usr/share/defaults/bro/scripts/base/protocols/irc/main.bro
/usr/share/defaults/bro/scripts/base/protocols/krb/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/krb/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/krb/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/krb/files.bro
/usr/share/defaults/bro/scripts/base/protocols/krb/main.bro
/usr/share/defaults/bro/scripts/base/protocols/modbus/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/modbus/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/modbus/main.bro
/usr/share/defaults/bro/scripts/base/protocols/mysql/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/mysql/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/mysql/main.bro
/usr/share/defaults/bro/scripts/base/protocols/ntlm/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/ntlm/main.bro
/usr/share/defaults/bro/scripts/base/protocols/pop3/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/pop3/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/radius/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/radius/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/radius/main.bro
/usr/share/defaults/bro/scripts/base/protocols/rdp/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/rdp/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/rdp/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/rdp/main.bro
/usr/share/defaults/bro/scripts/base/protocols/rfb/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/rfb/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/rfb/main.bro
/usr/share/defaults/bro/scripts/base/protocols/sip/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/sip/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/sip/main.bro
/usr/share/defaults/bro/scripts/base/protocols/smb/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/smb/const-dos-error.bro
/usr/share/defaults/bro/scripts/base/protocols/smb/const-nt-status.bro
/usr/share/defaults/bro/scripts/base/protocols/smb/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/smtp/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/smtp/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/smtp/entities.bro
/usr/share/defaults/bro/scripts/base/protocols/smtp/files.bro
/usr/share/defaults/bro/scripts/base/protocols/smtp/main.bro
/usr/share/defaults/bro/scripts/base/protocols/snmp/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/snmp/main.bro
/usr/share/defaults/bro/scripts/base/protocols/socks/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/socks/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/socks/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/socks/main.bro
/usr/share/defaults/bro/scripts/base/protocols/ssh/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/ssh/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/ssh/main.bro
/usr/share/defaults/bro/scripts/base/protocols/ssl/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/ssl/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/ssl/ct-list.bro
/usr/share/defaults/bro/scripts/base/protocols/ssl/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/ssl/files.bro
/usr/share/defaults/bro/scripts/base/protocols/ssl/main.bro
/usr/share/defaults/bro/scripts/base/protocols/ssl/mozilla-ca-list.bro
/usr/share/defaults/bro/scripts/base/protocols/syslog/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/syslog/consts.bro
/usr/share/defaults/bro/scripts/base/protocols/syslog/main.bro
/usr/share/defaults/bro/scripts/base/protocols/tunnels/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/tunnels/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/xmpp/__load__.bro
/usr/share/defaults/bro/scripts/base/protocols/xmpp/dpd.sig
/usr/share/defaults/bro/scripts/base/protocols/xmpp/main.bro
/usr/share/defaults/bro/scripts/base/utils/active-http.bro
/usr/share/defaults/bro/scripts/base/utils/addrs.bro
/usr/share/defaults/bro/scripts/base/utils/conn-ids.bro
/usr/share/defaults/bro/scripts/base/utils/dir.bro
/usr/share/defaults/bro/scripts/base/utils/directions-and-hosts.bro
/usr/share/defaults/bro/scripts/base/utils/email.bro
/usr/share/defaults/bro/scripts/base/utils/exec.bro
/usr/share/defaults/bro/scripts/base/utils/files.bro
/usr/share/defaults/bro/scripts/base/utils/geoip-distance.bro
/usr/share/defaults/bro/scripts/base/utils/json.bro
/usr/share/defaults/bro/scripts/base/utils/numbers.bro
/usr/share/defaults/bro/scripts/base/utils/paths.bro
/usr/share/defaults/bro/scripts/base/utils/patterns.bro
/usr/share/defaults/bro/scripts/base/utils/queue.bro
/usr/share/defaults/bro/scripts/base/utils/site.bro
/usr/share/defaults/bro/scripts/base/utils/strings.bro
/usr/share/defaults/bro/scripts/base/utils/thresholds.bro
/usr/share/defaults/bro/scripts/base/utils/time.bro
/usr/share/defaults/bro/scripts/base/utils/urls.bro
/usr/share/defaults/bro/scripts/broctl/__load__.bro
/usr/share/defaults/bro/scripts/broctl/auto.bro
/usr/share/defaults/bro/scripts/broctl/check.bro
/usr/share/defaults/bro/scripts/broctl/main.bro
/usr/share/defaults/bro/scripts/broctl/process-trace.bro
/usr/share/defaults/bro/scripts/broctl/standalone.bro
/usr/share/defaults/bro/scripts/broxygen/__load__.bro
/usr/share/defaults/bro/scripts/broxygen/example.bro
/usr/share/defaults/bro/scripts/policy/files/x509/log-ocsp.bro
/usr/share/defaults/bro/scripts/policy/frameworks/communication/listen.bro
/usr/share/defaults/bro/scripts/policy/frameworks/control/controllee.bro
/usr/share/defaults/bro/scripts/policy/frameworks/control/controller.bro
/usr/share/defaults/bro/scripts/policy/frameworks/dpd/detect-protocols.bro
/usr/share/defaults/bro/scripts/policy/frameworks/dpd/packet-segment-logging.bro
/usr/share/defaults/bro/scripts/policy/frameworks/files/detect-MHR.bro
/usr/share/defaults/bro/scripts/policy/frameworks/files/entropy-test-all-files.bro
/usr/share/defaults/bro/scripts/policy/frameworks/files/extract-all-files.bro
/usr/share/defaults/bro/scripts/policy/frameworks/files/hash-all-files.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/do_expire.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/do_notice.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/__load__.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/conn-established.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/dns.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/file-hashes.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/file-names.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/http-headers.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/http-url.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/pubkey-hashes.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/smtp-url-extraction.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/smtp.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/ssl.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/where-locations.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/seen/x509.bro
/usr/share/defaults/bro/scripts/policy/frameworks/intel/whitelist.bro
/usr/share/defaults/bro/scripts/policy/frameworks/packet-filter/shunt.bro
/usr/share/defaults/bro/scripts/policy/frameworks/signatures/detect-windows-shells.sig
/usr/share/defaults/bro/scripts/policy/frameworks/software/version-changes.bro
/usr/share/defaults/bro/scripts/policy/frameworks/software/vulnerable.bro
/usr/share/defaults/bro/scripts/policy/frameworks/software/windows-version-detection.bro
/usr/share/defaults/bro/scripts/policy/integration/barnyard2/__load__.bro
/usr/share/defaults/bro/scripts/policy/integration/barnyard2/main.bro
/usr/share/defaults/bro/scripts/policy/integration/barnyard2/types.bro
/usr/share/defaults/bro/scripts/policy/integration/collective-intel/__load__.bro
/usr/share/defaults/bro/scripts/policy/integration/collective-intel/main.bro
/usr/share/defaults/bro/scripts/policy/misc/capture-loss.bro
/usr/share/defaults/bro/scripts/policy/misc/detect-traceroute/__load__.bro
/usr/share/defaults/bro/scripts/policy/misc/detect-traceroute/detect-low-ttls.sig
/usr/share/defaults/bro/scripts/policy/misc/detect-traceroute/main.bro
/usr/share/defaults/bro/scripts/policy/misc/dump-events.bro
/usr/share/defaults/bro/scripts/policy/misc/known-devices.bro
/usr/share/defaults/bro/scripts/policy/misc/load-balancing.bro
/usr/share/defaults/bro/scripts/policy/misc/loaded-scripts.bro
/usr/share/defaults/bro/scripts/policy/misc/profiling.bro
/usr/share/defaults/bro/scripts/policy/misc/scan.bro
/usr/share/defaults/bro/scripts/policy/misc/stats.bro
/usr/share/defaults/bro/scripts/policy/misc/trim-trace-file.bro
/usr/share/defaults/bro/scripts/policy/protocols/conn/known-hosts.bro
/usr/share/defaults/bro/scripts/policy/protocols/conn/known-services.bro
/usr/share/defaults/bro/scripts/policy/protocols/conn/mac-logging.bro
/usr/share/defaults/bro/scripts/policy/protocols/conn/vlan-logging.bro
/usr/share/defaults/bro/scripts/policy/protocols/conn/weirds.bro
/usr/share/defaults/bro/scripts/policy/protocols/dhcp/known-devices-and-hostnames.bro
/usr/share/defaults/bro/scripts/policy/protocols/dns/auth-addl.bro
/usr/share/defaults/bro/scripts/policy/protocols/dns/detect-external-names.bro
/usr/share/defaults/bro/scripts/policy/protocols/ftp/detect-bruteforcing.bro
/usr/share/defaults/bro/scripts/policy/protocols/ftp/detect.bro
/usr/share/defaults/bro/scripts/policy/protocols/ftp/software.bro
/usr/share/defaults/bro/scripts/policy/protocols/http/detect-sqli.bro
/usr/share/defaults/bro/scripts/policy/protocols/http/detect-webapps.bro
/usr/share/defaults/bro/scripts/policy/protocols/http/detect-webapps.sig
/usr/share/defaults/bro/scripts/policy/protocols/http/header-names.bro
/usr/share/defaults/bro/scripts/policy/protocols/http/software-browser-plugins.bro
/usr/share/defaults/bro/scripts/policy/protocols/http/software.bro
/usr/share/defaults/bro/scripts/policy/protocols/http/var-extraction-cookies.bro
/usr/share/defaults/bro/scripts/policy/protocols/http/var-extraction-uri.bro
/usr/share/defaults/bro/scripts/policy/protocols/krb/ticket-logging.bro
/usr/share/defaults/bro/scripts/policy/protocols/modbus/known-masters-slaves.bro
/usr/share/defaults/bro/scripts/policy/protocols/modbus/track-memmap.bro
/usr/share/defaults/bro/scripts/policy/protocols/mysql/software.bro
/usr/share/defaults/bro/scripts/policy/protocols/rdp/indicate_ssl.bro
/usr/share/defaults/bro/scripts/policy/protocols/smb/__load__.bro
/usr/share/defaults/bro/scripts/policy/protocols/smb/dpd.sig
/usr/share/defaults/bro/scripts/policy/protocols/smb/files.bro
/usr/share/defaults/bro/scripts/policy/protocols/smb/main.bro
/usr/share/defaults/bro/scripts/policy/protocols/smb/smb1-main.bro
/usr/share/defaults/bro/scripts/policy/protocols/smb/smb2-main.bro
/usr/share/defaults/bro/scripts/policy/protocols/smtp/blocklists.bro
/usr/share/defaults/bro/scripts/policy/protocols/smtp/detect-suspicious-orig.bro
/usr/share/defaults/bro/scripts/policy/protocols/smtp/entities-excerpt.bro
/usr/share/defaults/bro/scripts/policy/protocols/smtp/software.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssh/detect-bruteforcing.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssh/geo-data.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssh/interesting-hostnames.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssh/software.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssl/expiring-certs.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssl/extract-certs-pem.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssl/heartbleed.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssl/known-certs.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssl/log-hostcerts-only.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssl/notary.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssl/validate-certs.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssl/validate-ocsp.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssl/validate-sct.bro
/usr/share/defaults/bro/scripts/policy/protocols/ssl/weak-keys.bro
/usr/share/defaults/bro/scripts/policy/tuning/__load__.bro
/usr/share/defaults/bro/scripts/policy/tuning/defaults/__load__.bro
/usr/share/defaults/bro/scripts/policy/tuning/defaults/extracted_file_limits.bro
/usr/share/defaults/bro/scripts/policy/tuning/defaults/packet-fragments.bro
/usr/share/defaults/bro/scripts/policy/tuning/defaults/warnings.bro
/usr/share/defaults/bro/scripts/policy/tuning/json-logs.bro
/usr/share/defaults/bro/scripts/policy/tuning/track-all-assets.bro
/usr/share/defaults/bro/scripts/site/local-logger.bro
/usr/share/defaults/bro/scripts/site/local-manager.bro
/usr/share/defaults/bro/scripts/site/local-proxy.bro
/usr/share/defaults/bro/scripts/site/local-worker.bro
/usr/share/defaults/bro/scripts/site/local.bro
/usr/share/man/man1/bro-cut.1
/usr/share/man/man1/trace-summary.1
/usr/share/man/man8/bro.8
/usr/share/man/man8/broctl.8
/var/lib/bro/broctl-config.sh

%files dev
%defattr(-,root,root,-)

%files -n broker
%defattr(-,root,root,-)
/usr/lib/libbroker.so
/usr/lib/libbroker.so.0
/usr/lib/libbroker.so.0.7.0

%files -n broker-dev
%defattr(-,root,root,-)
/usr/include/broker/address.hh
/usr/include/broker/broker.h
/usr/include/broker/broker.hh
/usr/include/broker/data.hh
/usr/include/broker/endpoint.hh
/usr/include/broker/enum_value.hh
/usr/include/broker/incoming_connection_status.hh
/usr/include/broker/message.hh
/usr/include/broker/message_queue.hh
/usr/include/broker/outgoing_connection_status.hh
/usr/include/broker/peering.hh
/usr/include/broker/port.hh
/usr/include/broker/queue.hh
/usr/include/broker/report.hh
/usr/include/broker/store/backend.hh
/usr/include/broker/store/clone.hh
/usr/include/broker/store/expiration_time.hh
/usr/include/broker/store/frontend.hh
/usr/include/broker/store/identifier.hh
/usr/include/broker/store/master.hh
/usr/include/broker/store/memory_backend.hh
/usr/include/broker/store/query.hh
/usr/include/broker/store/response.hh
/usr/include/broker/store/result.hh
/usr/include/broker/store/rocksdb_backend.hh
/usr/include/broker/store/sequence_num.hh
/usr/include/broker/store/snapshot.hh
/usr/include/broker/store/sqlite_backend.hh
/usr/include/broker/store/value.hh
/usr/include/broker/subnet.hh
/usr/include/broker/time_duration.hh
/usr/include/broker/time_point.hh
/usr/include/broker/topic.hh
/usr/include/broker/util/hash.hh
/usr/include/broker/util/meta.hh
/usr/include/broker/util/none.hh
/usr/include/broker/util/operators.hh
/usr/include/broker/util/optional.hh
/usr/include/broker/util/variant.hh

%files -n libbroccoli
%defattr(-,root,root,-)
/usr/bin/broccoli-config
/usr/lib/libbroccoli.a
/usr/lib/libbroccoli.so
/usr/lib/libbroccoli.so.5
/usr/lib/libbroccoli.so.5.1.0

%files -n libbroccoli-data
%defattr(-,root,root,-)
/usr/share/defaults/bro/config/broccoli.conf

%files -n libbroccoli-dev
%defattr(-,root,root,-)
/usr/include/broccoli.h

%files -n broctl
%defattr(-,root,root,-)
/usr/lib/broctl/BroControl/__init__.py
/usr/lib/broctl/BroControl/brocmd.py
/usr/lib/broctl/BroControl/broctl.py
/usr/lib/broctl/BroControl/cmdresult.py
/usr/lib/broctl/BroControl/config.py
/usr/lib/broctl/BroControl/control.py
/usr/lib/broctl/BroControl/cron.py
/usr/lib/broctl/BroControl/doc.py
/usr/lib/broctl/BroControl/events.py
/usr/lib/broctl/BroControl/exceptions.py
/usr/lib/broctl/BroControl/execute.py
/usr/lib/broctl/BroControl/install.py
/usr/lib/broctl/BroControl/lock.py
/usr/lib/broctl/BroControl/node.py
/usr/lib/broctl/BroControl/options.py
/usr/lib/broctl/BroControl/plugin.py
/usr/lib/broctl/BroControl/pluginreg.py
/usr/lib/broctl/BroControl/printdoc.py
/usr/lib/broctl/BroControl/py3bro.py
/usr/lib/broctl/BroControl/ssh_runner.py
/usr/lib/broctl/BroControl/state.py
/usr/lib/broctl/BroControl/util.py
/usr/lib/broctl/BroControl/utilcurses.py
/usr/lib/broctl/BroControl/version.py
/usr/lib/broctl/SubnetTree.py
/usr/lib/broctl/_SubnetTree.so
/usr/lib/broctl/_broccoli_intern.so
/usr/lib/broctl/_pybroker.so
/usr/lib/broctl/broccoli.py
/usr/lib/broctl/broccoli_intern.py
/usr/lib/broctl/plugins/TestPlugin.py
/usr/lib/broctl/plugins/lb_custom.py
/usr/lib/broctl/plugins/lb_myricom.py
/usr/lib/broctl/plugins/lb_pf_ring.py
/usr/lib/broctl/plugins/ps.py
/usr/lib/broctl/pybroker.py
/usr/share/broctl/scripts/archive-log
/usr/share/broctl/scripts/broctl-config.sh
/usr/share/broctl/scripts/check-config
/usr/share/broctl/scripts/crash-diag
/usr/share/broctl/scripts/delete-log
/usr/share/broctl/scripts/expire-crash
/usr/share/broctl/scripts/expire-logs
/usr/share/broctl/scripts/helpers/check-pid
/usr/share/broctl/scripts/helpers/df
/usr/share/broctl/scripts/helpers/first-line
/usr/share/broctl/scripts/helpers/get-childs
/usr/share/broctl/scripts/helpers/start
/usr/share/broctl/scripts/helpers/stop
/usr/share/broctl/scripts/helpers/to-bytes.awk
/usr/share/broctl/scripts/helpers/top
/usr/share/broctl/scripts/make-archive-name
/usr/share/broctl/scripts/post-terminate
/usr/share/broctl/scripts/postprocessors/summarize-connections
/usr/share/broctl/scripts/run-bro
/usr/share/broctl/scripts/run-bro-on-trace
/usr/share/broctl/scripts/send-mail
/usr/share/broctl/scripts/set-bro-path
/usr/share/broctl/scripts/stats-to-csv
/usr/share/broctl/scripts/update
/usr/lib/broctl/BroControl/__pycache__/__init__.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/brocmd.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/broctl.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/cmdresult.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/config.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/control.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/cron.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/doc.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/events.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/exceptions.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/execute.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/install.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/lock.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/node.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/options.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/plugin.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/pluginreg.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/printdoc.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/py3bro.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/ssh_runner.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/state.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/util.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/utilcurses.cpython-36.pyc
/usr/lib/broctl/BroControl/__pycache__/version.cpython-36.pyc
/usr/lib/broctl/__pycache__/SubnetTree.cpython-36.pyc
/usr/lib/broctl/__pycache__/broccoli.cpython-36.pyc
/usr/lib/broctl/__pycache__/broccoli_intern.cpython-36.pyc
/usr/lib/broctl/__pycache__/pybroker.cpython-36.pyc
/usr/lib/broctl/plugins/__pycache__/TestPlugin.cpython-36.pyc
/usr/lib/broctl/plugins/__pycache__/lb_custom.cpython-36.pyc
/usr/lib/broctl/plugins/__pycache__/lb_myricom.cpython-36.pyc
/usr/lib/broctl/plugins/__pycache__/lb_pf_ring.cpython-36.pyc
/usr/lib/broctl/plugins/__pycache__/ps.cpython-36.pyc

%files -n broctl-data
%defattr(-,root,root,-)
/usr/share/defaults/bro/config/broctl.cfg

