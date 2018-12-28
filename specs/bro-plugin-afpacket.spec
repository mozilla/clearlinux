Name     : bro-plugin-afpacket
Version  : 1.3.79edee2
Release  : 1
URL      : https://bro.org
Source   : http://clb0.security.allizom.org/bro-plugin-afpacket-1.3.79edee2.tar
Source1  : http://clb0.security.allizom.org/bro-2.5.9271b2032.tar
Patch0   : broafconfig.patch
Summary  : No detailed summary available
Group    : Development/Tools
License  : GPL-3.0+

%description
No detailed description available

%prep
%setup
%setup -T -D -a 1
%patch0 -p1

%build
export LANG=C
cd ./bro-2.5.9271b2032 && ./configure && cd build/src && make bifcl
./bifcl /home/clear/rpmbuild/BUILD/bro-plugin-afpacket-1.3.79edee2/bro-2.5.9271b2032/src/const.bif
./bifcl /home/clear/rpmbuild/BUILD/bro-plugin-afpacket-1.3.79edee2/bro-2.5.9271b2032/src/types.bif 
./bifcl /home/clear/rpmbuild/BUILD/bro-plugin-afpacket-1.3.79edee2/bro-2.5.9271b2032/src/event.bif 
./bifcl /home/clear/rpmbuild/BUILD/bro-plugin-afpacket-1.3.79edee2/bro-2.5.9271b2032/src/reporter.bif 
cd ../../..
./configure --bro-dist=./bro-2.5.9271b2032 --install-root=${_prefix}/usr/lib/bro/plugins --with-kernel=/tmp/linux-4.14.21 && make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%make_install

%files
%defattr(-,root,root,0644)
/usr/lib/bro/plugins/Bro_AF_Packet/__bro_plugin__
/usr/lib/bro/plugins/Bro_AF_Packet/broctl/__pycache__/af_packet.cpython-36.pyc
/usr/lib/bro/plugins/Bro_AF_Packet/broctl/af_packet.py
/usr/lib/bro/plugins/Bro_AF_Packet/lib/Bro-AF_Packet.linux-x86_64.so
/usr/lib/bro/plugins/Bro_AF_Packet/lib/bif/__load__.bro
/usr/lib/bro/plugins/Bro_AF_Packet/lib/bif/af_packet.bif.bro
/usr/lib/bro/plugins/Bro_AF_Packet/scripts/__load__.bro
/usr/lib/bro/plugins/Bro_AF_Packet/scripts/init.bro
