Name: illegal
Version: 1.0
Release: 1%{?dist}
Summary: Dummy RPM
License: MIT
BuildArch: noarch

%description
  A dummy RPM package.

%install
  mkdir -p %{buildroot}/usr/share/dummy
  echo hello > %{buildroot}/usr/share/dummy/file.txt

%files
  /usr/share/dummy/file.txt

%changelog
* Thu Jul 02 2026 Nick Clifton  <nickc@redhat.com> - 1.0-1
- Initial release.
