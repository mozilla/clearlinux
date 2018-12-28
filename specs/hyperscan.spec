Name     : hyperscan
Version  : 4.7.0
Release  : 1
URL      : https://github.com/intel/hyperscan
Source0  : https://github.com/intel/hyperscan/archive/v4.7.0.tar.gz
Source1  : https://ayera.dl.sourceforge.net/project/boost/boost/1.66.0/boost_1_66_0.tar.bz2
Summary  : No detailed summary available
Group    : Development/Tools
License  : GPL-3.0+

%description
No detailed description available

%prep
%setup
%setup -T -D -a 1

%build
cd boost_1_66_0
./bootstrap.sh --prefix=./tmp
./b2 install
#./configure --prefix=%{_prefix} --build-type=Release --no-examples --no-qt-examples --no-protobuf-examples --no-curl-examples --no-unit-tests --no-opencl --no-nexus --no-cash --no-benchmarks --no-riac && make  %{?_smp_mflags}

%install
rm -rf %{buildroot}
#make install DESTDIR=

%files
%defattr(-,root,root,0644)
