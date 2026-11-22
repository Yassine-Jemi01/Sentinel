# Fedora RPM packaging notes

Sentinel's Fedora package is maintained separately from the Python wheel metadata. Use Fedora's Python packaging macros and build from an immutable upstream release archive.

## Spec requirements

The current package uses:

- `Name: sentinel`
- `License: MIT`
- `BuildArch: noarch`
- `BuildRequires: python3-devel`
- `BuildRequires: pyproject-rpm-macros`
- `%pyproject_buildrequires -r` to include runtime requirements from project metadata.
- `%pyproject_wheel`, `%pyproject_install`, and `%pyproject_save_files -l sentinel`.

Do not point `Source0` at a moving branch. Use the archive for the exact release tag submitted for review. Do not use the old `v0.1.0` archive for this readiness branch; it predates the changes here. Create a new release tag only after the branch has been tested.

## Manual page

Install the manual page in the RPM build root after `%pyproject_install`:

```spec
install -Dpm 0644 man/sentinel.1 %{buildroot}%{_mandir}/man1/sentinel.1
```

Include it in `%files`:

```spec
%{_mandir}/man1/sentinel.1*
```

Keep the generated Python file list from `%pyproject_save_files`; do not replace it with a hand-maintained list of package modules.

## Build and review checklist

1. Build the SRPM and binary RPM with Mock for the target Fedora release.
2. Repeat the build against Rawhide.
3. Run `rpmlint` on the spec, SRPM, and binary RPM.
4. Verify that the installed command is `/usr/bin/sentinel` and the man page is `sentinel(1)`.
5. Test `sentinel version`, `sentinel check`, and `sentinel update` after installation.
6. Confirm that RPM-managed updates are performed by DNF and that the GitHub installer refuses to shadow an RPM-managed `/usr/bin/sentinel`.
7. Keep build artifacts and local databases out of the source package.
